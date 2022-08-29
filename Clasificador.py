#!/usr/bin/env python
import sys, subprocess
import joblib
from prettytable import PrettyTable 
import signal 
import os 
import numpy as np 
import pandas as pd

datos = pd.read_csv('datos.csv', header=0)
datos = datos.drop(datos.columns[0],axis='columns')

#pryu = "ryu-manager ryu.app.simple_monitor_13"
pryu = "ryu-manager controlador.py"
flows = {}
rep = {}

class Flow:
    def __init__(self,TotLen_Bwd_Pkts,Fwd_Pkt_Len_Max,Fwd_Pkt_Len_Min,Fwd_Pkt_Len_Std,Bwd_Pkt_Len_Min,Bwd_Pkt_Len_Std,Flow_Byts_s,Flow_Pkts_s,Flow_IAT_Mean,Flow_IAT_Min,Fwd_IAT_Std,Bwd_IAT_Tot,Bwd_IAT_Std,Bwd_IAT_Max,Bwd_Header_Len,Pkt_Len_Max,Pkt_Len_Mean,Pkt_Len_Std,Pkt_Len_Var,Down_Up_Ratio,Fwd_Seg_Size_Avg,Bwd_Seg_Size_Avg,Init_Bwd_Win_Byts,Active_Min,Idle_Std,Puerto_Origen,Puerto_Destino,IP_Origen,IP_Destino,Seno_Hora,Coseno_Hora):
        self.TotLen_Bwd_Pkts =   TotLen_Bwd_Pkts
        self.Fwd_Pkt_Len_Max =   Fwd_Pkt_Len_Max
        self.Fwd_Pkt_Len_Min =   Fwd_Pkt_Len_Min
        self.Fwd_Pkt_Len_Std =   Fwd_Pkt_Len_Std
        self.Bwd_Pkt_Len_Min =   Bwd_Pkt_Len_Min
        self.Bwd_Pkt_Len_Std =   Bwd_Pkt_Len_Std
        self.Flow_Byts_s =       Flow_Byts_s
        self.Flow_Pkts_s =       Flow_Pkts_s
        self.Flow_IAT_Mean =     Flow_IAT_Mean
        self.Flow_IAT_Min =      Flow_IAT_Min
        self.Fwd_IAT_Std =       Fwd_IAT_Std
        self.Bwd_IAT_Tot =       Bwd_IAT_Tot
        self.Bwd_IAT_Std =       Bwd_IAT_Std
        self.Bwd_IAT_Max =       Bwd_IAT_Max
        self.Bwd_Header_Len =    Bwd_Header_Len
        self.Pkt_Len_Max =       Pkt_Len_Max
        self.Pkt_Len_Mean =      Pkt_Len_Mean
        self.Pkt_Len_Std =       Pkt_Len_Std
        self.Pkt_Len_Var =       Pkt_Len_Var
        self.Down_Up_Ratio =     Down_Up_Ratio
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

    #updates the attributes in the forward flow direction
    def updateforward(self, packets, bytes, curr_time):
        self.forward_delta_packets = packets - self.forward_packets
        self.forward_packets = packets
        if curr_time != self.time_start: self.forward_avg_pps = packets/float(curr_time-self.time_start)
        if curr_time != self.forward_last_time: self.forward_inst_pps = self.forward_delta_packets/float(curr_time-self.forward_last_time)
        
        self.forward_delta_bytes = bytes - self.forward_bytes
        self.forward_bytes = bytes
        if curr_time != self.time_start: self.forward_avg_bps = bytes/float(curr_time-self.time_start)
        if curr_time != self.forward_last_time: self.forward_inst_bps = self.forward_delta_bytes/float(curr_time-self.forward_last_time)
        self.forward_last_time = curr_time
        
        if (self.forward_delta_bytes==0 or self.forward_delta_packets==0): #if the flow did not receive any packets of bytes
            self.forward_status = 'INACTIVE'
        else:
            self.forward_status = 'ACTIVE'

    #updates the attributes in the reverse flow direction
    def updatereverse(self, packets, bytes, curr_time):
        self.reverse_delta_packets = packets - self.reverse_packets
        self.reverse_packets = packets
        if curr_time != self.time_start: self.reverse_avg_pps = packets/float(curr_time-self.time_start)
        if curr_time != self.reverse_last_time: self.reverse_inst_pps = self.reverse_delta_packets/float(curr_time-self.reverse_last_time)
        
        self.reverse_delta_bytes = bytes - self.reverse_bytes
        self.reverse_bytes = bytes
        if curr_time != self.time_start: self.reverse_avg_bps = bytes/float(curr_time-self.time_start)
        if curr_time != self.reverse_last_time: self.reverse_inst_bps = self.reverse_delta_bytes/float(curr_time-self.reverse_last_time)
        self.reverse_last_time = curr_time

        if (self.reverse_delta_bytes==0 or self.reverse_delta_packets==0): #if the flow did not receive any packets of bytes
            self.reverse_status = 'INACTIVE'
        else:
            self.reverse_status = 'ACTIVE'

def printHelp():
    print("\tPara clasificar usando svm usa: sudo python3 Clasificador.py svm")
    print("\tPara clasificar usando random forest usa: sudo python3 Clasificador.py rf")
    print("\tPara clasificar usando regresión logística usa: sudo python3 Clasificador.py lr")
    return

def printclassifier(model):
    x = PrettyTable()
    x.field_names = ["Flow ID", "IP Origen", "IP Destino", "Puerto Origen","Puerto Destino","Tipo"]

    for key,flow in flows.items():
        features = np.asarray([flow.TotLen_Bwd_Pkts,flow.Fwd_Pkt_Len_Max,flow.Fwd_Pkt_Len_Min,flow.Fwd_Pkt_Len_Std,flow.Bwd_Pkt_Len_Min,flow.Bwd_Pkt_Len_Std,flow.Flow_Byts_s,flow.Flow_Pkts_s,flow.Flow_IAT_Mean,flow.Flow_IAT_Min,flow.Fwd_IAT_Std,flow.Bwd_IAT_Tot,flow.Bwd_IAT_Std,flow.Bwd_IAT_Max,flow.Bwd_Header_Len,flow.Pkt_Len_Max,flow.Pkt_Len_Mean,flow.Pkt_Len_Std,flow.Pkt_Len_Var,flow.Down_Up_Ratio,flow.Fwd_Seg_Size_Avg,flow.Bwd_Seg_Size_Avg,flow.Init_Bwd_Win_Byts,flow.Active_Min,flow.Idle_Std,flow.Puerto_Origen,flow.Puerto_Destino,flow.IP_Origen,flow.IP_Destino,flow.Seno_Hora,flow.Coseno_Hora]).reshape(1,-1) #convert to array so the model can understand the features properly
        
        label = model.predict(features.tolist()) #if model is supervised (logistic regression) then the label is the type of traffic
        
        #if the model is unsupervised, the label is a cluster number. Refer to Jupyter notebook to see how cluster numbers map to labels
        if label == 0: label = ['Normal']
        elif label == 1: label = ['Ataque']
        
        x.add_row([key, flow.IP_Origen, flow.IP_Destino,flow.Puerto_Origen,flow.Puerto_Destino,label[0]]) 
    print(x)#print output in pretty mode (i.e. formatted table)

def run_ryu(p,modelo):
    time = 0
    while True:
        #print 'going through loop'
        out = p.stdout.readline()
        print(out)
        if out == '' and p.poll() != None:
            break
        if out != '' and out.startswith(b'data'): #when Ryu 'simple_monitor_AK.py' script returns output
            print('KHEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE')
            fields = out.split(b'\t')[1:] #split the flow details
            
            fields = [f.decode(encoding='utf-8', errors='strict') for f in fields] #decode flow details 
            
            if fields[8] == '6':
                unique_id = '-'.join([fields[7],fields[6],fields[3],fields[2],fields[8]]) #create unique ID for flow based on switch ID, source host,and destination host
                print(unique_id)
            if fields[8] == '17':
                unique_id = '-'.join([fields[7],fields[6],fields[5],fields[4],fields[8]]) #create unique ID for flow based on switch ID, source host,and destination host
                print(unique_id)
            if fields[8] == '0':
                unique_id = '-'.join([fields[7],fields[6],fields[5],'0-0',fields[8]]) #create unique ID for flow based on switch ID, source host,and destination host
                print(unique_id)
            if unique_id in datos['Flow ID']:
                if rep[unique_id] >= 1:
                    fila = datos['Flow ID']==unique_id
                    fila = fila.iloc[rep[unique_id]]
                    flows[unique_id] = Flow(fila['TotLen Bwd Pkts'],fila['Fwd Pkt Len Max'],fila['Fwd Pkt Len Min'],fila['Fwd Pkt Len Std'],fila['Bwd Pkt Len Min'],fila['Bwd Pkt Len Std'],fila['Flow Byts/s'],fila['Flow Pkts/s'],fila['Flow IAT Mean'],fila['Flow IAT Min'],fila['Fwd IAT Std'],fila['Bwd IAT Tot'],fila['Bwd IAT Std'],fila['Bwd IAT Max'],fila['Bwd Header Len'],fila['Pkt Len Max'],fila['Pkt Len Mean'],fila['Pkt Len Std'],fila['Pkt Len Var'],fila['Down Up Ratio'],fila['Fwd Seg Size Avg'],fila['Bwd Seg Size Avg'],fila['Init Bwd Win Byts'],fila['Active Min'],fila['Idle Std'],fila['Puerto Origen'],fila['Puerto Destino'],fila['IP Origen'],fila['IP Destino'],fila['Seno Hora'],fila['Coseno Hora'])
                    rep[unique_id] = rep[unique_id] + 1
                else:
                    rep[unique_id] = 1
                    fila = datos['Flow ID']==unique_id
                    fila = fila.iloc[0]
                    flows[unique_id] = Flow(fila['TotLen Bwd Pkts'],fila['Fwd Pkt Len Max'],fila['Fwd Pkt Len Min'],fila['Fwd Pkt Len Std'],fila['Bwd Pkt Len Min'],fila['Bwd Pkt Len Std'],fila['Flow Byts/s'],fila['Flow Pkts/s'],fila['Flow IAT Mean'],fila['Flow IAT Min'],fila['Fwd IAT Std'],fila['Bwd IAT Tot'],fila['Bwd IAT Std'],fila['Bwd IAT Max'],fila['Bwd Header Len'],fila['Pkt Len Max'],fila['Pkt Len Mean'],fila['Pkt Len Std'],fila['Pkt Len Var'],fila['Down Up Ratio'],fila['Fwd Seg Size Avg'],fila['Bwd Seg Size Avg'],fila['Init Bwd Win Byts'],fila['Active Min'],fila['Idle Std'],fila['Puerto Origen'],fila['Puerto Destino'],fila['IP Origen'],fila['IP Destino'],fila['Seno Hora'],fila['Coseno Hora'])
            else:
                flows[unique_id] = Flow(fila['TotLen Bwd Pkts'],fila['Fwd Pkt Len Max'],fila['Fwd Pkt Len Min'],fila['Fwd Pkt Len Std'],fila['Bwd Pkt Len Min'],fila['Bwd Pkt Len Std'],fila['Flow Byts/s'],fila['Flow Pkts/s'],fila['Flow IAT Mean'],fila['Flow IAT Min'],fila['Fwd IAT Std'],fila['Bwd IAT Tot'],fila['Bwd IAT Std'],fila['Bwd IAT Max'],fila['Bwd Header Len'],fila['Pkt Len Max'],fila['Pkt Len Mean'],fila['Pkt Len Std'],fila['Pkt Len Var'],fila['Down Up Ratio'],fila['Fwd Seg Size Avg'],fila['Bwd Seg Size Avg'],fila['Init Bwd Win Byts'],fila['Active Min'],fila['Idle Std'],fila['Puerto Origen'],fila['Puerto Destino'],fila['IP Origen'],fila['IP Destino'],fila['Seno Hora'],fila['Coseno Hora'])
            #if unique_id in flows.keys():
                #flows[unique_id].updateforward(int(fields[6]),int(fields[7]),int(fields[0])) #update forward attributes with time, packet, and byte count
            #else:
               # rev_unique_id = hash(''.join([fields[1],fields[4],fields[3]])) #switch source and destination to generate same hash for src/dst and dst/src
                #if rev_unique_id in flows.keys():
                    #flows[rev_unique_id].updatereverse(int(fields[6]),int(fields[7]),int(fields[0])) #update reverse attributes with time, packet, and byte count
                #else:
                    #flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]), int(fields[7])) #create new flow object
            if time%10==0:
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
                    modelo = joblib.load('modelosvm.joblib')
                elif sys.argv[1]=="rf":
                    modelo = joblib.load('modelorf.joblib')
                elif sys.argv[1]=="lr":
                    modelo = joblib.load('modelolr.joblib')
                run_ryu(p,modelo)
        sys.exit()
