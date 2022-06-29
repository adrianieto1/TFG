#!/usr/bin/env python
import sys, subprocess
from joblib import load
import numpy as np

pryu = "ryu-manager controlador.py"
flows = {}

class Flow:
    def __init__(self,TotLen_Bwd_Pkts,Fwd_Pkt_Len_Max,Fwd_Pkt_Len_Min,Fwd_Pkt_Len_Std,Bwd_Pkt_Len_Min,Bwd_Pkt_Len_Std,Flow_Byts_s,Flow_Pkts_s,Flow_IAT_Mean,Flow_IAT_Min,Fwd_IAT_Std,Bwd_IAT_Tot,Bwd_IAT_Std,Bwd_IAT_Max,Bwd_Header_Len,Pkt_Len_Max,Pkt_Len_Mean,Pkt_Len_Std,Pkt_Len_Var,Down_Up_Ratio,Fwd_Seg_Size_Avg,Bwd_Seg_Size_Avg,Init_Bwd_Win_Byts,Active_Min,Idle_Std,Puerto_Origen,Puerto_Destino,IP_Origen,IP_Destino,Seno_Hora,Coseno_Hora):
        self.TotLen_Bwd_Pkts = TotLen_Bwd_Pkts
        self.Fwd_Pkt_Len_Max = Fwd_Pkt_Len_Max
        self.Fwd_Pkt_Len_Min = Fwd_Pkt_Len_Min
        self.Fwd_Pkt_Len_Std = Fwd_Pkt_Len_Std
        self.Bwd_Pkt_Len_Min = Bwd_Pkt_Len_Min
        self.Bwd_Pkt_Len_Std = Bwd_Pkt_Len_Std
        self.Flow_Byts_s =     Flow_Byts_s
        self.Flow_Pkts_s =     Flow_Pkts_s
        self.Flow_IAT_Mean =   Flow_IAT_Mean
        self.Flow_IAT_Min =    Flow_IAT_Min
        self.Fwd_IAT_Std =     Fwd_IAT_Std
        self.Bwd_IAT_Tot =     Bwd_IAT_Tot
        self.Bwd_IAT_Std =     Bwd_IAT_Std
        self.Bwd_IAT_Max =     Bwd_IAT_Max
        self.Bwd_Header_Len =  Bwd_Header_Len
        self.Pkt_Len_Max =     Pkt_Len_Max
        self.Pkt_Len_Mean =    Pkt_Len_Mean
        self.Pkt_Len_Std =     Pkt_Len_Std
        self.Pkt_Len_Var =     Pkt_Len_Var
        self.Down_Up_Ratio =   Down_Up_Ratio
        self.Fwd_Seg_Size_Avg =  Fwd_Seg_Size_Avg
        self.Bwd_Seg_Size_Avg =  Bwd_Seg_Size_Avg
        self.Init_Bwd_Win_Byts = Init_Bwd_Win_Byts
        self.Active_Min =        Active_Min
        self.Idle_Std =          Idle_Std
        self.Puerto_Origen =     Puerto_Origen
        self.Puerto_Destino =    Puerto_Destino
        self.IP_Origen =         IP_Origen
        self.IP_Destino=         IP_Destino
        self.Seno_Hora =         Seno_Hora
        self.Coseno_Hora =       Coseno_Hora

def printHelp():
    print("Uso: sudo python3 Clasificador.py [subcomando]")
    print("\tPara clasificar usando svm usa: sudo python3 Clasificador.py svm")
    print("\tPara clasificar usando random forest usa: sudo python3 Clasificador.py rf")
    print("\tPara clasificar usando regresión logística usa: sudo python3 Clasificador.py lr")
    return

def printclassifier(model):

    for key,flow in flows.items():
        features = np.asarray([flow.forward_delta_packets,flow.forward_delta_bytes,flow.forward_inst_pps,flow.forward_avg_pps,flow.forward_inst_bps, flow.forward_avg_bps, flow.reverse_delta_packets,flow.reverse_delta_bytes,flow.reverse_inst_pps,flow.reverse_avg_pps,flow.reverse_inst_bps,flow.reverse_avg_bps]).reshape(1,-1) #convert to array so the model can understand the features properly
        
        label = model.predict(features.tolist()) #if model is supervised (logistic regression) then the label is the type of traffic
        
        #if the model is unsupervised, the label is a cluster number. Refer to Jupyter notebook to see how cluster numbers map to labels
        if label == 0: label = ['dns']
        elif label == 1: label = ['ping']
        elif label == 2: label = ['telnet']
        elif label == 3: label = ['voice']
    print(label[0])

def run_ryu(p,modelo):
    time = 0
    while True:
        #print 'going through loop'
        out = p.stdout.readline()
        if out == '' and p.poll() != None:
            break
        if out != '' and out.startswith(b'data'): #when Ryu 'simple_monitor_AK.py' script returns output
            fields = out.split(b'\t')[1:] #split the flow details
            
            fields = [f.decode(encoding='utf-8', errors='strict') for f in fields] #decode flow details 
            
            unique_id = hash(''.join([fields[1],fields[3],fields[4]])) #create unique ID for flow based on switch ID, source host,and destination host
            if unique_id in flows.keys():
                flows[unique_id].updateforward(int(fields[6]),int(fields[7]),int(fields[0])) #update forward attributes with time, packet, and byte count
            else:
                rev_unique_id = hash(''.join([fields[1],fields[4],fields[3]])) #switch source and destination to generate same hash for src/dst and dst/src
                if rev_unique_id in flows.keys():
                    flows[rev_unique_id].updatereverse(int(fields[6]),int(fields[7]),int(fields[0])) #update reverse attributes with time, packet, and byte count
                else:
                    flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]), int(fields[7])) #create new flow object
            printclassifier(modelo)
        time += 1

if __name__ == '__main__':
    SUBCOMMANDS = ('svm', 'rf', 'lr')

    if len(sys.argv) < 2:
        print("ERROR: Número incorrecto de argumentos")
        printHelp()
        sys.exit();
    else:
        if len(sys.argv) == 2:
            if sys.argv[1] not in SUBCOMMANDS:
                print("ERROR: Subcomando desconocido")
                printHelp()
                sys.exit();
            else:
                p = subprocess.Popen(pryu, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if sys.argv[1]=="svm":
                    modelo = load('modelosvm.joblib')
                elif sys.argv[1]=="rf":
                    modelo = load('modelorf.joblib')
                elif sys.argv[1]=="lr":
                    modelo = load('modelolr.joblib')
                run_ryu(p,modelo)
        sys.exit()
