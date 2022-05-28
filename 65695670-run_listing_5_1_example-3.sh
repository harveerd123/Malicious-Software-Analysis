#!/bin/bash
python 65695670-listing_5_1-3.py -target_directory ~/malware_data_science/ch5/data/APT1_MALWARE_FAMILIES -output_dot_file 65695670-similarity_graph-3.dot
fdp -Tpng -o 65695670-similarity_graph-3.png 65695670-similarity_graph-3.dot
