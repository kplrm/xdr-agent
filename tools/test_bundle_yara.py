import unittest
from bundle_yara import build

class BundleTests(unittest.TestCase):
    def test_linux_selection_keeps_dependencies_and_excludes_other_platforms(self):
        source = r'''
import "pe"
private rule shared_helper { condition: true }
rule linux_fixture { meta: description="Linux test" strings: $a="braces { }" condition: $a and shared_helper }
rule windows_fixture { meta: description="Windows test" condition: pe.is_pe }
rule mac_fixture { meta: description="macOS test" condition: true }
rule ambiguous_fixture { condition: true }
'''
        text, catalog = build(source)
        self.assertEqual([r['name'] for r in catalog['rules']], ['shared_helper', 'linux_fixture'])
        self.assertNotIn('import "pe"', text)
        self.assertEqual(catalog['platform'], 'linux')
        self.assertEqual(build(source), (text, catalog))
    def test_dependency_on_foreign_rule_is_not_bundled(self):
        _, catalog = build('rule windows_helper { condition: true }\nrule linux_bad { condition: windows_helper }\nrule linux_good { condition: true }')
        self.assertEqual([r['name'] for r in catalog['rules']], ['linux_good'])
    def test_other_targets_and_invalid_input_fail(self):
        for source, platform in [('rule linux_a { condition: true }', 'windows'), ('rule linux_bad { condition: true', 'linux'), ('', 'linux')]:
            with self.assertRaises(ValueError):
                build(source, platform)

if __name__ == '__main__':
    unittest.main()
