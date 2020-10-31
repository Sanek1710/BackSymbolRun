import sys
out_file = None

def fopen(name):
    global out_file
    out_file = open(name, 'w')
    return out_file

def printf(*args):
    global out_file
    out = ''
    for obj in args:
        out += str(obj) + ' '
    if out_file is not None:
        print >> out_file, out
    else:
        print out

def fclose():
    global out_file
    out_file.close()