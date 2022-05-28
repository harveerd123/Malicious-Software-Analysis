#!/usr/bin/python

import argparse
import os
import networkx
from networkx.drawing.nx_pydot import write_dot
import itertools
import pprint
import pefile
from capstone import *


"""
Copyright (c) 2015, Joshua Saxe
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name 'Joshua Saxe' nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL JOSHUA SAXE BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""



def jaccard(set1,set2):
    """
    Compute the Jaccard distance between two sets by taking
    their intersection, union and then dividing the number
    of elements in the intersection by the number of elements
    in their union.
    """
    intersection = set1.intersection(set2)
    intersection_length = float(len(intersection))
    union = set1.union(set2)
    union_length = float(len(union))
    if (union_length == 0 or intersection_length == 0): #ADDED IF STATEMENT TO PREVENT ERRORS WHEN TRYING VERY LARGE N VALUES FOR NGRAMS
        return 0.0
    else:
        return intersection_length / union_length

def getstrings(fullpath):
    """
    Extract strings from the binary indicated by the 'fullpath'
    parameter, and then return the set of unique strings in
    the binary.
    """
    strings = os.popen("strings '{0}'".format(fullpath)).read()
    strings = set(strings.split("\n"))
    return strings

def getImportAddrTable(fullpath): #ADDED METHOD TO RETRIEVE IAT
    pe = pefile.PE(fullpath)
    pe.parse_data_directories()
    ImportAddrTable_list = set()

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imports in entry.imports:
            ImportAddrTable_list.add(hex(imports.address))
    return ImportAddrTable_list

def getNGrams(fullpath, n): #ADDED METHOD TO GET NGRAMS
    pe = pefile.PE(fullpath)
    entrypoint = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    entrypoint_address = entrypoint + pe.OPTIONAL_HEADER.ImageBase
    binary_code = pe.get_memory_mapped_image()[entrypoint:entrypoint+5000]
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32) 
    nGramSet = set()
    instruction_list = []
    in_list = []
    list_l = []

    for instruction in disassembler.disasm(binary_code, entrypoint_address):
    	instruction_list.append(("%s\t%s" %(instruction.mnemonic, instruction.op_str)))
    
    for instr in instruction_list:
    	ins = instr.encode('ascii', 'ignore')
    	in_list.append(ins)

      

    for i in range(len(in_list) - (n-1)):
    	thistuple = tuple(in_list[i:i+n])
    	list_l.append(thistuple)


      
    count = 0
    while count != (len(list_l)):
    	gettuple = (list_l[count])
    	nGramSet.add(gettuple)
    	count = count + 1

    return nGramSet

def pecheck(fullpath):
    """
    Do a cursory sanity check to make sure 'fullpath' is
    a Windows PE executable (PE executables start with the
    two bytes 'MZ')
    """
    return open(fullpath).read(2) == "MZ"

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Identify similarities between malware samples and build similarity graph"
    )

    parser.add_argument(
        "-target_directory",
        help="Directory containing malware"
    )

    parser.add_argument(
        "-output_dot_file",
        help="Where to save the output graph DOT file"
    )

    parser.add_argument(
        "-n",
        help = "NGrams number", type = int

    ) #ADDED ANOTHER ARGUMENT SO YOU CAN SPECIFY N(NGRAM NUMBER) 

    parser.add_argument(
        "-jaccard_index_threshold","-j",dest="threshold",type=float,
        default=0.8,help="Threshold above which to create an 'edge' between samples"
    ) #CHANGED ARGUMENTS SO THAT THEY ARE SAME AS LAB5 ARGUMENTS

    args = parser.parse_args()
    malware_paths = [] # where we'll store the malware file paths
    malware_attributes = dict() # where we'll store the malware strings
    graph = networkx.Graph() # the similarity graph

    for root, dirs, paths in os.walk(args.target_directory):
        # walk the target directory tree and store all of the file paths
        for path in paths:
            full_path = os.path.join(root,path)
            malware_paths.append(full_path)

    # filter out any paths that aren't PE files
    malware_paths = filter(pecheck, malware_paths)

    # get and store the strings for all of the malware PE files
    for path in malware_paths:
        args = parser.parse_args() #ADDED SO WE CAN GET PARAMTER FOR N(NGRAM NUMBER)
        attributes = getNGrams(path, args.n) #ATTRIBUTES NOW GOT FROM getNGrams METHOD IMPLEMENTED
        print "Extracted {0} attributes from {1} ...".format(len(attributes),path)
        malware_attributes[path] = attributes

        # add each malware file to the graph
        graph.add_node(path,label=os.path.split(path)[-1][:10])

    # iterate through all pairs of malware
    for malware1,malware2 in itertools.combinations(malware_paths,2):

        # compute the jaccard distance for the current pair
        jaccard_index = jaccard(malware_attributes[malware1],malware_attributes[malware2])

        # if the jaccard distance is above the threshold add an edge
        if jaccard_index > args.threshold:
            print malware1,malware2,jaccard_index
            graph.add_edge(malware1,malware2,penwidth=1+(jaccard_index-args.threshold)*10)

    # write the graph to disk so we can visualize it
    write_dot(graph,args.output_dot_file)
