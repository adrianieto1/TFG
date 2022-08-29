#!/usr/bin/env python
from pathlib import Path
import os

directory_name= 'pcaps'

open_files = Path(directory_name).glob('*.pcap')
for file in open_files:
    comando = 'sudo tcpreplay -i h1-eth0 -t ' + str(file)
    os.system(comando)