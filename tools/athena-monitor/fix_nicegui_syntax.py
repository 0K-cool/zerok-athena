#!/usr/bin/env python3
"""
Fix NiceGUI .add() syntax to use 'with' context managers
"""
import re

with open('athena_monitor_v2.py', 'r') as f:
    content = f.read()

# Pattern 1: Simple single-line .add() with label
# ui.element('th').classes('...').add(ui.label('TEXT'))
# -> with ui.element('th').classes('...'):
#        ui.label('TEXT')

def fix_single_line_add(match):
    indent = match.group(1)
    element_type = match.group(2)
    classes = match.group(3)
    label_content = match.group(4)

    return f"{indent}with ui.element('{element_type}').classes('{classes}'):\n{indent}    ui.label({label_content})"

# Pattern for single-line .add()
pattern1 = r"^(\s+)ui\.element\('(\w+)'\)\.classes\('([^']+)'\)\.add\(ui\.label\(([^)]+)\)\)"
content = re.sub(pattern1, fix_single_line_add, content, flags=re.MULTILINE)

# Pattern 2: Multi-line .add() calls
# ui.element('td').classes('...').add(
#     ui.label(...)
# )
# -> with ui.element('td').classes('...'):
#        ui.label(...)

def fix_multiline_add(match):
    indent = match.group(1)
    element_type = match.group(2)
    classes = match.group(3)
    label_content = match.group(4)

    return f"{indent}with ui.element('{element_type}').classes('{classes}'):\n{indent}    ui.label({label_content})"

pattern2 = r"^(\s+)ui\.element\('(\w+)'\)\.classes\('([^']+)'\)\.add\(\s*\n\s+ui\.label\(([^)]+)\)\s*\n\s*\)"
content = re.sub(pattern2, fix_multiline_add, content, flags=re.MULTILINE | re.DOTALL)

# Also fix cases where the label is on next line
pattern3 = r"^(\s+)ui\.element\('(\w+)'\)\.classes\('([^']+)'\)\.add\(\s*ui\.label\(([^)]+)\)\s*\)"
content = re.sub(pattern3, fix_multiline_add, content, flags=re.MULTILINE)

with open('athena_monitor_v2_fixed.py', 'w') as f:
    f.write(content)

print("✅ Fixed NiceGUI syntax")
print("📝 Output written to: athena_monitor_v2_fixed.py")
