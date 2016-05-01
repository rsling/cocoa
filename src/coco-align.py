# -*- coding: utf-8 -*-

import argparse
import os.path
import sys
import bs4
import diff_match_patch as dmp
import pickle
import zlib
import base64
import re
from itertools import cycle, izip

def visible(element):
    if element.parent.name in ['style', 'script', '[document]', 'head', 'title', 'meta']:
        return False
    elif isinstance(element,bs4.element.Comment):
        return False
    return True


def cleane(s):
    s = re.sub(r'&(quot|apos|lt|gt|amp);', ' ', s)
    s = re.sub(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', 'uriblank', s)
    s = re.sub(r'([\w\-\.]+@(\w[\w\-]+\.)+[\w\-]+)', 'emailblank', s)
    return s


def xor(data, key):
    return ''.join(chr(ord(c)^ord(k)) for c,k in izip(data, cycle(key)))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('target', help='Target COCO/COW-XML file.')
    parser.add_argument('source', help='Source text file (dirty).')
    parser.add_argument('output', help='Output COCOA file.')
    parser.add_argument('--erase', action='store_true', help="erase outout files if present")
    args = parser.parse_args()

    dmp.Diff_EditCost = 4

    # Check input files.
    infiles = [args.target, args.source]
    for fn in infiles:
        if not os.path.exists(fn):
            sys.exit("Input file does not exist: " + fn)
  
    # Check (potentially erase) output files.
    outfiles = [args.output]
    for fn in outfiles:
        if fn is not None and os.path.exists(fn):
            if args.erase:
                try:
                    os.remove(fn)
                except:
                    sys.exit("Cannot delete pre-existing output file: " + fn)
            else:
                sys.exit("Output file already exists: " + fn)

    # Open outfile.
    outfile = open(args.output, 'w')

    # Compile regex matchers.
    alpha  = re.compile(r'[\W\d_]', re.UNICODE)
    allpha = re.compile(r'^[^\W\d_]+$', re.UNICODE)
    docstart = re.compile(r'^<doc .+> *$', re.UNICODE)
    docextract = re.compile(r'^(<doc .*url=")([^"]+)(".*ip=")([^"]+)(".*host=")([^"]+)(".*>) *$', re.UNICODE)

    # Read both documents. In real tool from WARC and COCOA files.
    with open(args.source, 'r') as source_file:
        source = source_file.read()

    # Import the target (= corpus) document.
    target = []
    for l in open(args.target, 'r'):
        line = l.decode('utf-8').strip()
        if len(line) > 0:
            target.append(line)

    # Get only text, not XML.
    target_text = [line.split('\t')[0] for line in target if line[0] != '<']
    target_text = [cleane(l) for l in target_text]

    # Filter non-alpha.
    target_text = [alpha.sub(r' ', line) for line in target_text]

    # Compress whitespace.
    target_pure = ' '.join(target_text)
    target_pure = ' '.join(target_pure.split())

    # Import and strip HTML source.
    source_soup = bs4.BeautifulSoup(source, "lxml")
    source_text = source_soup.findAll(text=True)
    source_text = filter(visible, source_text)
    source_pure = [alpha.sub(r' ', line) for line in source_text]
    source_pure = ' '.join(source_pure)
    source_pure = ' '.join(source_pure.split())

    # Get the diff between source and target.
    differ = dmp.diff_match_patch()
    diffs = differ.diff_main(source_pure, target_pure)
    differ.diff_cleanupEfficiency(diffs)

    # Get edit distance. TODO Abort if too high.
    distance = differ.diff_levenshtein(diffs)

    # Create a patch to later re-create target from source.
    patches = differ.patch_make(target_pure, diffs)

    # Pickle patches, compress, encode to Base64 ASCII.
    dump = pickle.dumps(patches) 
    dump64 = base64.b64encode(zlib.compress(dump))
    
    # Restore patches from string.
    restored = pickle.loads(zlib.decompress(base64.b64decode(dump64)))

    re_target = differ.patch_apply(restored, source_pure)
    re_list = list(set(re_target[0].split(' ')))

    # Scramble sensitive information.
    key = str(zlib.adler32(re_target[0].encode('utf-8')))

    print 'Target size        = ' + str(len(target))
    print 'Source size        = ' + str(len(source))
    print 'Levenshtein        = ' + str(int(distance))
    print 'Pickeld patch size = ' + str(len(dump))
    print 'Base64 patch size  = ' + str(len(dump64)) 

    for t in target:
        if t[0] == '<':
            if docstart.match(t):
                url  = docextract.sub(r'\2', t)
                ip   = docextract.sub(r'\4', t)
                host = docextract.sub(r'\6', t)
                mangled_url = base64.b64encode(xor(url.encode('utf-8'), key))
                mangled_ip = base64.b64encode(xor(ip.encode('utf-8'), key))
                mangled_host = base64.b64encode(xor(host.encode('utf-8'), key))
                outfile.write((docextract.sub(r'\1',t) + mangled_url + docextract.sub(r'\3',t) + mangled_ip + docextract.sub(r'\5',t) + mangled_host + docextract.sub(r'\7',t)).encode('utf-8'))
                outfile.write('\n'.join(['\n<diff>', '\n'.join([dump64[i:i+72] for i in range(0, len(dump64), 72)]), '</diff>']) + '\n')
            else:
                outfile.write(t.encode('utf-8') + '\n')
        else:
            ts = t.split('\t')
            if allpha.match(ts[0]):
                try:
                    if ts[0] == ts[2]:
                        outfile.write(('@' + str(re_list.index(ts[0])) + '@' + '\t' + ts[1] + '\t@id@\t' + '\t'.join(ts[3:]) ).encode('utf-8') + '\n')
                    else:
                        outfile.write(('@' + str(re_list.index(ts[0])) + '@' + '\t' + '\t'.join(ts[1:]) ).encode('utf-8') + '\n')
                except:
                    outfile.write('\t'.join(ts).encode('utf-8') + '\n')
            else:
                outfile.write(t.encode('utf-8') + '\n')


if __name__ == "__main__":
    main()

