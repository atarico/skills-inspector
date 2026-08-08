import sys
def align(text):
    return '\n'.join(line.rstrip() for line in text.splitlines())
print(align(sys.stdin.read()))
