#!/bin/bash
python 65695670-listing_5_1-1.py -target_directory ~/malware_data_science/ch5/data/APT1_MALWARE_FAMILIES -output_dot_file 65695670-similarity_graph-1.dot
fdp -Tpng -o 65695670-similarity_graph-1.png 65695670-similarity_graph-1.dot
