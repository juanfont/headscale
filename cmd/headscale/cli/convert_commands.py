#!/usr/bin/env python3
"""Script to convert all commands to use WithClient pattern"""

import re
import sys
import os

def convert_command(content):
    """Convert a single command to use WithClient pattern"""
    
    # Pattern to match the gRPC client setup
    pattern = r'(\t+)ctx, client, conn, cancel := newHeadscaleCLIWithConfig\(\)\n\t+defer cancel\(\)\n\t+defer conn\.Close\(\)\n\n'
    
    # Find all occurrences
    matches = list(re.finditer(pattern, content))
    
    if not matches:
        return content
    
    # Process each match from the end to avoid offset issues
    for match in reversed(matches):
        indent = match.group(1)
        start_pos = match.start()
        end_pos = match.end()
        
        # Find the end of the Run function
        remaining_content = content[end_pos:]
        
        # Find the matching closing brace for the Run function
        brace_count = 0
        func_end = -1
        
        for i, char in enumerate(remaining_content):
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count < 0:  # Found the closing brace
                    func_end = i
                    break
        
        if func_end == -1:
            continue
            
        # Extract the function body
        func_body = remaining_content[:func_end]
        
        # Indent the function body
        indented_body = '\n'.join(indent + '\t' + line if line.strip() else line 
                                 for line in func_body.split('\n'))
        
        # Create the new function with WithClient
        new_func = f"""{indent}err := WithClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {{
{indented_body}
{indent}\treturn nil
{indent}}})
{indent}
{indent}if err != nil {{
{indent}\treturn
{indent}}}"""
        
        # Replace the old pattern with the new one
        content = content[:start_pos] + new_func + '\n' + content[end_pos + func_end:]
    
    return content

def process_file(filepath):
    """Process a single Go file"""
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        
        # Check if context is already imported
        if 'import (' in content and '"context"' not in content:
            # Add context import
            content = content.replace(
                'import (',
                'import (\n\t"context"'
            )
        
        # Convert commands
        new_content = convert_command(content)
        
        # Write back if changed
        if new_content != content:
            with open(filepath, 'w') as f:
                f.write(new_content)
            print(f"Updated {filepath}")
        else:
            print(f"No changes needed for {filepath}")
            
    except Exception as e:
        print(f"Error processing {filepath}: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 convert_commands.py <go_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        sys.exit(1)
    
    process_file(filepath)