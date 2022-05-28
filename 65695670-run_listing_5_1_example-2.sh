#!/bin/bash
python 65695670-listing_5_1-2.py -target_directory ~/malware_data_science/ch5/data/APT1_MALWARE_FAMILIES -output_dot_file 65695670-similarity_graph-2-3.dot -n 3
fdp -Tpng -o 65695670-similarity_graph-2-3.png 65695670-similarity_graph-2-3.dot

python 65695670-listing_5_1-2.py -target_directory ~/malware_data_science/ch5/data/APT1_MALWARE_FAMILIES -output_dot_file 65695670-similarity_graph-2-7.dot -n 7
fdp -Tpng -o 65695670-similarity_graph-2-7.png 65695670-similarity_graph-2-7.dot

python 65695670-listing_5_1-2.py -target_directory ~/malware_data_science/ch5/data/APT1_MALWARE_FAMILIES -output_dot_file 65695670-similarity_graph-2-11.dot -n 11
fdp -Tpng -o 65695670-similarity_graph-2-11.png 65695670-similarity_graph-2-11.dot



