<?php
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeTraverser;

$file = $argv[1] ?? '';
if (!$file || !is_file($file)) { fwrite(STDERR, "file not found\n"); exit(2); }
$code = file_get_contents($file);
$parser = (new ParserFactory)->createForNewestSupportedVersion();
try { $ast = $parser->parse($code); }
catch (Throwable $e) { fwrite(STDERR, $e->getMessage()."\n"); exit(3); }

$classStack = [];
function closureScope(Node $n): string {
    global $classStack;
    $c = end($classStack);
    return ($c ? $c . '::' : '') . '{closure}@' . $n->getStartLine();
}
function nm($x): string {
    if ($x instanceof Node\Name || $x instanceof Node\Identifier) return $x->toString();
    return 'dynamic';
}
function args(array $as): array {
    return array_map(fn($a) => $a instanceof Node\Arg ? expr($a->value) : ['type' => 'other'], $as);
}

// Recursive expression serializer. The Python analyzer walks this tree for taint propagation.
function expr(?Node $n): array {
    if ($n === null) return ['type' => 'null'];
    if ($n instanceof Node\Expr\Variable) return ['type' => 'var', 'name' => is_string($n->name) ? $n->name : 'dynamic'];
    if ($n instanceof Node\Expr\ArrayDimFetch) return ['type' => 'array_dim', 'base' => expr($n->var), 'dim' => $n->dim ? expr($n->dim) : null];
    if ($n instanceof Node\Expr\PropertyFetch) return ['type' => 'property', 'base' => expr($n->var), 'name' => nm($n->name)];
    if ($n instanceof Node\Expr\FuncCall) return ['type' => 'call', 'name' => nm($n->name), 'args' => args($n->args)];
    if ($n instanceof Node\Expr\MethodCall || $n instanceof Node\Expr\NullsafeMethodCall)
        return ['type' => 'method_call', 'method' => nm($n->name), 'base' => expr($n->var), 'args' => args($n->args)];
    if ($n instanceof Node\Expr\StaticCall) return ['type' => 'static_call', 'class' => nm($n->class), 'method' => nm($n->name), 'args' => args($n->args)];
    if ($n instanceof Node\Expr\BinaryOp) return ['type' => 'binary', 'op' => $n->getOperatorSigil(), 'left' => expr($n->left), 'right' => expr($n->right)];
    if ($n instanceof Node\Scalar\InterpolatedString)
        return ['type' => 'interp', 'parts' => array_map(fn($p) => $p instanceof Node\Expr ? expr($p) : ['type' => 'string'], $n->parts)];
    if ($n instanceof Node\Expr\Cast) return ['type' => 'cast', 'to' => strtolower(rtrim((new \ReflectionClass($n))->getShortName(), '_')), 'expr' => expr($n->expr)];
    if ($n instanceof Node\Expr\Ternary) return ['type' => 'ternary', 'if' => $n->if ? expr($n->if) : expr($n->cond), 'else' => expr($n->else)];
    if ($n instanceof Node\Expr\Assign) return ['type' => 'assign', 'left' => expr($n->var), 'right' => expr($n->expr)];
    if ($n instanceof Node\Expr\Closure || $n instanceof Node\Expr\ArrowFunction) return ['type' => 'closure', 'scope' => closureScope($n)];
    if ($n instanceof Node\Expr\Array_)
        return ['type' => 'array', 'items' => array_values(array_filter(array_map(
            fn($i) => $i instanceof Node\ArrayItem ? ['key' => $i->key ? expr($i->key) : null, 'value' => expr($i->value)] : null, $n->items)))];
    if ($n instanceof Node\Expr\ConstFetch) return ['type' => 'const', 'name' => $n->name->toString()];
    if ($n instanceof Node\Expr\ClassConstFetch && $n->name instanceof Node\Identifier && $n->name->toString() === 'class')
        return ['type' => 'string', 'value' => nm($n->class)];
    if ($n instanceof Node\Scalar\String_) return ['type' => 'string', 'value' => $n->value];
    if ($n instanceof Node\Scalar\Int_) return ['type' => 'number', 'value' => $n->value];
    return ['type' => 'other', 'class' => get_class($n)];
}

$tr = new NodeTraverser();
$visitor = new class extends \PhpParser\NodeVisitorAbstract {
    public array $out = [];
    private array $scopes = [];
    private array $pushed = [];
    public function enterNode(Node $n) {
        global $classStack;
        $kind = (new \ReflectionClass($n))->getShortName();
        $isClass = $n instanceof Node\Stmt\Class_ || $n instanceof Node\Stmt\Trait_ || $n instanceof Node\Stmt\Enum_;
        if ($isClass) $classStack[] = ($n->name ? $n->name->toString() : 'anon');
        $cls = end($classStack) ?: null;
        $fn = null;
        if ($n instanceof Node\Stmt\Function_) $fn = $n->name->toString();
        elseif ($n instanceof Node\Stmt\ClassMethod) $fn = ($cls ? $cls . '::' : '') . $n->name->toString();
        elseif ($n instanceof Node\Expr\Closure || $n instanceof Node\Expr\ArrowFunction) $fn = closureScope($n);
        if ($fn !== null) $this->scopes[] = $fn;
        $this->pushed[spl_object_id($n)] = ($fn !== null) ? 1 : 0;
        $x = ['kind' => $kind, 'line' => $n->getStartLine(), 'scope' => end($this->scopes) ?: ''];
        if ($fn !== null) {
            $x['class'] = $cls;
            $x['params'] = array_map(fn($p) => ($p->var instanceof Node\Expr\Variable && is_string($p->var->name)) ? $p->var->name : 'dynamic', $n->params);
            if ($n instanceof Node\Stmt\Function_ || $n instanceof Node\Stmt\ClassMethod) $x['name'] = $n->name->toString();
        }
        if ($n instanceof Node\Expr\Variable) $x['name'] = is_string($n->name) ? $n->name : 'dynamic';
        if ($n instanceof Node\Expr\FuncCall) { $x['name'] = nm($n->name); $x['args'] = args($n->args); }
        if ($n instanceof Node\Expr\MethodCall || $n instanceof Node\Expr\NullsafeMethodCall) { $x['method'] = nm($n->name); $x['base'] = expr($n->var); $x['args'] = args($n->args); }
        if ($n instanceof Node\Expr\StaticCall) { $x['class'] = nm($n->class); $x['method'] = nm($n->name); $x['args'] = args($n->args); }
        if ($n instanceof Node\Stmt\Echo_) $x['args'] = array_map(fn($e) => expr($e), $n->exprs);
        if ($n instanceof Node\Expr\Print_ || $n instanceof Node\Expr\Include_ || $n instanceof Node\Expr\Eval_) $x['args'] = [expr($n->expr)];
        if ($n instanceof Node\Expr\ArrayDimFetch) { $x['base'] = expr($n->var); $x['dim'] = $n->dim ? expr($n->dim) : null; }
        if ($n instanceof Node\Expr\Assign) { $x['left'] = expr($n->var); $x['right'] = expr($n->expr); }
        $this->out[] = $x;
        return null;
    }
    public function leaveNode(Node $n) {
        global $classStack;
        if (!empty($this->pushed[spl_object_id($n)])) array_pop($this->scopes);
        if ($n instanceof Node\Stmt\Class_ || $n instanceof Node\Stmt\Trait_ || $n instanceof Node\Stmt\Enum_) array_pop($classStack);
        return null;
    }
};
$tr->addVisitor($visitor);
$tr->traverse($ast);
echo json_encode(['file' => $file, 'nodes' => $visitor->out], JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
