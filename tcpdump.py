#!/usr/bin/env python
import os
comando = 'sudo tcpdump host 10.51.1.105 > -w prueba -q &'
os.system(comando)