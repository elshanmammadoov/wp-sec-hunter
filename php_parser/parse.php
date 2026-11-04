<?php
declare(strict_types=1);
require dirname(__DIR__) . '/vendor/autoload.php';
use PhpParser\ParserFactory;
use PhpParser\Node;
use PhpParser\NodeTraverser;
use PhpParser\NodeVisitor\NameResolver;

$file = $argv[1] ?? '';
if (!$file || !is_file($file)) { fwrite(STDERR, "file not found\n"); exit(2); }
$code = file_get_contents($file);
$parser = (new ParserFactory)->createForNewestSupportedVersion();
try { $ast = $parser->parse($code); }
catch (Throwable $e) { fwrite(STDERR, $e->getMessage()."\n"); exit(3); }

function expr(Node $n): array {
    if ($n instanceof Node\Expr\Variable) return ['type'=>'var','name'=>is_string($n->name)?$n->name:'dynamic'];
    if ($n instanceof Node\Expr\ArrayDimFetch) return ['type'=>'array_dim','base'=>expr($n->var),'dim'=>$n->dim ? expr($n->dim) : null];
    if ($n instanceof Node\Expr\PropertyFetch) return ['type'=>'property','base'=>expr($n->var),'name'=>$n->name instanceof Node\Identifier?$n->name->toString():'dynamic'];
    if ($n instanceof Node\Expr\FuncCall) return ['type'=>'call','name'=>$n->name instanceof Node\Name?$n->name->toString():'dynamic','args'=>array_map(fn($a)=>expr($a->value),$n->args)];
    if ($n instanceof Node\Expr\MethodCall) return ['type'=>'method_call','method'=>$n->name instanceof Node\Identifier?$n->name->toString():'dynamic','base'=>expr($n->var),'args'=>array_map(fn($a)=>expr($a->value),$n->args)];
    if ($n instanceof Node\Scalar\String_) return ['type'=>'string','value'=>$n->value];
    if ($n instanceof Node\Scalar\LNumber) return ['type'=>'number','value'=>$n->value];
    return ['type'=>get_class($n)];
}

$nodes=[];
$tr = new NodeTraverser();
$visitor=new class($nodes) extends \PhpParser\NodeVisitorAbstract {
    public array $out=[]; public function enterNode(Node $n){
        $kind=(new \ReflectionClass($n))->getShortName();
        $x=['kind'=>$kind,'line'=>$n->getStartLine()];
        if ($n instanceof Node\Expr\Variable) $x['name']=is_string($n->name)?$n->name:'dynamic';
        if ($n instanceof Node\Expr\FuncCall) { $x['name']=$n->name instanceof Node\Name?$n->name->toString():'dynamic'; $x['args']=array_map(fn($a)=>expr($a->value),$n->args); }
        if ($n instanceof Node\Expr\MethodCall) { $x['method']=$n->name instanceof Node\Identifier?$n->name->toString():'dynamic'; $x['base']=expr($n->var); $x['args']=array_map(fn($a)=>expr($a->value),$n->args); }
        if ($n instanceof Node\Expr\ArrayDimFetch) { $x['base']=expr($n->var); $x['dim']=$n->dim?expr($n->dim):null; }
        if ($n instanceof Node\Expr\Assign) { $x['left']=expr($n->var); $x['right']=expr($n->expr); }
        $this->out[]=$x;
    }
};
$tr->addVisitor($visitor); $tr->traverse($ast);
echo json_encode(['file'=>$file,'nodes'=>$visitor->out], JSON_UNESCAPED_SLASHES);
