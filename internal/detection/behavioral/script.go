package behavioral

// Script detects obfuscated and malicious script execution.
//
// Detection techniques:
//  - Base64-encoded command lines (bash -c "$(echo ... | base64 -d)")
//  - Hex-encoded payloads
//  - Python/Perl/Ruby one-liners from unusual parents
//  - Large inline scripts via -c flag
//  - Pipes from curl/wget directly to interpreter (curl | bash)
//  - eval/exec with dynamic content
//
// MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1027 (Obfuscated Files)

// TODO: Implement script detection
// - Analyze command-line args of interpreters (bash, python, perl, ruby, node)
// - Detect base64/hex encoding patterns in command lines
// - Detect pipe chains: download → decode → execute
// - Calculate "obfuscation score" based on entropy and patterns
// - Alert when score exceeds threshold
