from analyzer.core.models import Finding, Location, Program
from analyzer.core.rules.registry import RuleRegistry
from analyzer.core.graph import DeclarationResolver


def api_reviews(program: Program, rules: RuleRegistry) -> list[Finding]:
    findings = []
    resolver = DeclarationResolver(program)
    review_prefixes = tuple('Landroid/webkit/WebSettings;->' + name + '(' for name in (
        'setJavaScriptEnabled', 'setAllowFileAccess', 'setAllowContentAccess',
        'setAllowFileAccessFromFileURLs', 'setAllowUniversalAccessFromFileURLs',
        'setMixedContentMode', 'setSafeBrowsingEnabled', 'setGeolocationEnabled',
        'setJavaScriptCanOpenWindowsAutomatically', 'setSupportMultipleWindows')) + (
                       'Landroid/webkit/WebView;->addJavascriptInterface(',
                       'Landroid/webkit/WebView;->setWebContentsDebuggingEnabled(',
                       'Landroid/webkit/SslErrorHandler;->proceed(', 'Ljavax/crypto/Cipher;->getInstance(',
                       'Ljava/security/MessageDigest;->getInstance(', 'Ljava/lang/Class;->forName(',
                       'Ljava/lang/System;->loadLibrary(', 'Ljava/lang/System;->load(') + tuple(
                       'Landroid/util/Log;->' + name + '(' for name in
                       ('v', 'd', 'i', 'w', 'e', 'wtf', 'println'))
    for method in program.methods.values():
        for ins in method.instructions:
            if not ins.opcode.startswith('invoke'):
                continue
            target = resolver.target(ins.target)
            rule = next((r for r in rules.config['sinks'] if any(target.startswith(s) for s in r['signatures'])), None)
            if rule or target.startswith(review_prefixes):
                findings.append(Finding((rule['id'] if rule else 'AOS-API-001') + '-REVIEW',
                    'Review API context: ' + ins.target, 'API presence only. No vulnerability is asserted.',
                    rule['category'] if rule else 'INFO', location=Location(method.class_name, method.signature, ins.offset),
                    confidence='CERTAIN', sink=ins.target, evidence=[ins.text],
                    bytecode=f'{ins.offset:04x}  {ins.text}'))
    return findings
