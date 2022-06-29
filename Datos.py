#!/usr/bin/env python
# coding: utf-8

# # Análisis do conxunto de datos InSDN

# ### Introducción

# InSDN é un conxunto de datos exhaustivo de SDN para a evaluación dun sistema de detección de intrusos. Este dataset contén as distintas categorías de ataques que poden ocurrir en diferentes elementos do estándar SDN.

# Este conxunto de datos está dividido en tres grupos diferentes dependendo do tipo de tráfico e das máquinas destino dos ataques.

# O primeiro grupo só inclue tráfico normal, que pode incluir varios servicios de aplicacións como HTTPS, SSL, DNS, Email...

# O segundo grupo contén ataques de tráfico cuxo obxetivo e o servidor mealsplotable 2.

# No terceiro e último grupo considéranse ataques na máquina OVS.

# O tráfico está capturado para cada categoría na máquina destino e na interfaz do controlador SDN.

# ### Insertado de datos en Python

# Os datos insertaránse en python usando a librería pandas

# In[1]:


import pandas as pd
pd.options.display.max_rows = None
pd.options.display.max_columns = None
#from sklearnex import patch_sklearn
#patch_sklearn()


# In[2]:


ficherogrupo1 = 'Normal_data.csv'


# In[3]:


benigno = pd.read_csv(ficherogrupo1, header=0)


# In[4]:


ficherogrupo2 = 'metasploitable-2.csv'


# In[5]:


meta = pd.read_csv(ficherogrupo2, header=0)


# In[6]:


ficherogrupo3 = 'OVS.csv'


# In[7]:


ovs = pd.read_csv(ficherogrupo3, header=0)


# ### Tratamiento de los datos

# Vamos a realizar distintos cambios en los conjuntos de datos para hacer que estos se adecuen lo más posible a lo que queremos realizar con ellos

# Primero vamos a crear una columna nueva en cada uno de los tres datasets distintos que tenemos para pasar a tener una clasificación binaria, es decir, sólo vamos a distinguir entre ataques y tráfico normal, y no vamos a distinguir los ataques como se hacen en los datasets. Para esto vamos a crear una columna nueva en cada dataset en la que el valor en el conjunto benigno sea 0 (tráfico normal), mientras que en los conjuntos meta y ovs el valor será de 1 (tráfico de ataque).

# In[8]:


benigno = benigno.assign(Tipo = 0)
meta = meta.assign(Tipo = 1)
ovs = ovs.assign(Tipo = 1)


# In[9]:


ovs['Label'].unique()


# In[10]:


datos = pd.concat([benigno, meta, ovs])
##datos['Puerto Origen'] = datos.apply((lambda x: "suuu" if (sp==443) else "chiquito" for sp in (datos['Src Port']), axis=1))


# ### Análise dos datos

# Primeiro vamos a analizar os datos que se atopan en cada csv do conxunto de datos (que se corresponden a cada un dos dos grupos comentados anteriormente), que xuntamos no paso anterior na variable datos, e ver que datos contén cada un. Só vamos a imprimir as dez primeiras filas por comodidade.

# In[11]:


print(benigno.shape)
benigno.head(10)


# In[12]:


print(meta.shape)
meta.head(10)


# In[13]:


print(ovs.shape)
ovs.head(10)


# In[14]:


print(datos.shape)
datos.isna().sum().sort_values()


# In[15]:


datos.info()


# Cómo vemos cada táboa contén 84 columnas, máis unha adicional que foi a que añadin anteriormente, que se corresponden cada un con un atributo distinto. Tampouco se representan todas, polas limitacións de impresión por pantalla. Tras isto vamos a analizar que datos aportan máis información e cales aportan menos usando matrices de correlación e vendo cando datos únicos contén cada columna. Tamén vemos na columna que non falta ningún dato no conxunto de datos.

# In[16]:


lista = []
lista.append(len(datos['Flow ID'].unique()))
lista.append(len(datos['Src IP'].unique()))
lista.append(len(datos['Src Port'].unique()))
lista.append(len(datos['Dst IP'].unique()))
lista.append(len(datos['Dst Port'].unique()))
lista.append(len(datos['Protocol'].unique()))
lista.append(len(datos['Timestamp'].unique()))
lista.append(len(datos['Flow Duration'].unique()))
lista.append(len(datos['Tot Fwd Pkts'].unique()))
lista.append(len(datos['Tot Bwd Pkts'].unique()))
lista.append(len(datos['TotLen Fwd Pkts'].unique()))
lista.append(len(datos['TotLen Bwd Pkts'].unique()))
lista.append(len(datos['Fwd Pkt Len Max'].unique()))
lista.append(len(datos['Fwd Pkt Len Min'].unique()))
lista.append(len(datos['Fwd Pkt Len Mean'].unique()))
lista.append(len(datos['Fwd Pkt Len Std'].unique()))
lista.append(len(datos['Bwd Pkt Len Max'].unique()))
lista.append(len(datos['Bwd Pkt Len Min'].unique()))
lista.append(len(datos['Bwd Pkt Len Mean'].unique()))
lista.append(len(datos['Bwd Pkt Len Std'].unique()))
print(lista)


# In[17]:


lista = []
lista.append(len(datos['Flow Byts/s'].unique()))
lista.append(len(datos['Flow Pkts/s'].unique()))
lista.append(len(datos['Flow IAT Mean'].unique()))
lista.append(len(datos['Flow IAT Std'].unique()))
lista.append(len(datos['Flow IAT Max'].unique()))
lista.append(len(datos['Flow IAT Min'].unique()))
lista.append(len(datos['Fwd IAT Tot'].unique()))
lista.append(len(datos['Fwd IAT Mean'].unique()))
lista.append(len(datos['Fwd IAT Std'].unique()))
lista.append(len(datos['Fwd IAT Max'].unique()))
lista.append(len(datos['Fwd IAT Min'].unique()))
lista.append(len(datos['Bwd IAT Tot'].unique()))
lista.append(len(datos['Bwd IAT Mean'].unique()))
lista.append(len(datos['Bwd IAT Std'].unique()))
lista.append(len(datos['Bwd IAT Max'].unique()))
lista.append(len(datos['Bwd IAT Min'].unique()))
lista.append(len(datos['Fwd PSH Flags'].unique()))
lista.append(len(datos['Bwd PSH Flags'].unique()))
lista.append(len(datos['Fwd URG Flags'].unique()))
lista.append(len(datos['Bwd URG Flags'].unique()))
print(lista)


# In[18]:


lista = []
lista.append(len(datos['Fwd Header Len'].unique()))
lista.append(len(datos['Bwd Header Len'].unique()))
lista.append(len(datos['Fwd Pkts/s'].unique()))
lista.append(len(datos['Bwd Pkts/s'].unique()))
lista.append(len(datos['Pkt Len Min'].unique()))
lista.append(len(datos['Pkt Len Max'].unique()))
lista.append(len(datos['Pkt Len Mean'].unique()))
lista.append(len(datos['Pkt Len Std'].unique()))
lista.append(len(datos['Pkt Len Var'].unique()))
lista.append(len(datos['FIN Flag Cnt'].unique()))
lista.append(len(datos['SYN Flag Cnt'].unique()))
lista.append(len(datos['RST Flag Cnt'].unique()))
lista.append(len(datos['PSH Flag Cnt'].unique()))
lista.append(len(datos['ACK Flag Cnt'].unique()))
lista.append(len(datos['URG Flag Cnt'].unique()))
lista.append(len(datos['CWE Flag Count'].unique()))
lista.append(len(datos['ECE Flag Cnt'].unique()))
lista.append(len(datos['Down/Up Ratio'].unique()))
lista.append(len(datos['Pkt Size Avg'].unique()))
print(lista)


# In[19]:


lista = []
lista.append(len(datos['Fwd Seg Size Avg'].unique()))
lista.append(len(datos['Bwd Seg Size Avg'].unique()))
lista.append(len(datos['Fwd Byts/b Avg'].unique()))
lista.append(len(datos['Fwd Pkts/b Avg'].unique()))
lista.append(len(datos['Fwd Blk Rate Avg'].unique()))
lista.append(len(datos['Bwd Byts/b Avg'].unique()))
lista.append(len(datos['Bwd Pkts/b Avg'].unique()))
lista.append(len(datos['Bwd Blk Rate Avg'].unique()))
lista.append(len(datos['Subflow Fwd Pkts'].unique()))
lista.append(len(datos['Subflow Fwd Byts'].unique()))
lista.append(len(datos['Subflow Bwd Pkts'].unique()))
lista.append(len(datos['Subflow Bwd Byts'].unique()))
lista.append(len(datos['Init Fwd Win Byts'].unique()))
lista.append(len(datos['Init Bwd Win Byts'].unique()))
lista.append(len(datos['Fwd Act Data Pkts'].unique()))
lista.append(len(datos['Fwd Seg Size Min'].unique()))
lista.append(len(datos['Active Mean'].unique()))
lista.append(len(datos['Active Std'].unique()))
lista.append(len(datos['Active Max'].unique()))
lista.append(len(datos['Active Min'].unique()))
lista.append(len(datos['Idle Mean'].unique()))
lista.append(len(datos['Idle Std'].unique()))
lista.append(len(datos['Idle Max'].unique()))
lista.append(len(datos['Idle Min'].unique()))
lista.append(len(datos['Label'].unique()))
lista.append(len(datos['Tipo'].unique()))
print(lista)


# ### Visualización dos datos 

# Tras ver os datos máis relevantes vamos a mostrar unhas gráficas que nos amosen máis información acerca dos datos que se atopan na base de datos.

# In[20]:


import matplotlib.pyplot as plt
plt.close("all")
fig = plt.figure(figsize=(6,6))
datos.Tipo.value_counts().plot(kind='bar')
plt.title('Nº de flows de ataque e de tráfico normal')


# In[21]:


fig = plt.figure(figsize=(12,12))
plt.subplot2grid((2,2),(0,0))
datos[datos['Tipo']==0].Protocol.value_counts().plot(kind='bar')
plt.title('Nº paquetes por protocolo tráfico normal')
plt.subplot2grid((2,2),(0,1))
datos[datos['Tipo']==1].Protocol.value_counts().plot(kind='bar')
plt.title('Nº paquetes por protocolo tráfico de ataque')


# In[22]:


fig = plt.figure(figsize=(14,14))
plt.subplot2grid((3,2),(0,0))
datos[datos['Tipo']==0]['Dst Port'].plot(kind='kde')
datos[datos['Tipo']==1]['Dst Port'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,100000)
plt.title('Puerto de destino')
plt.subplot2grid((3,2),(0,1))
datos[datos['Tipo']==0]['Src Port'].plot(kind='kde')
datos[datos['Tipo']==1]['Src Port'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,100000)
plt.title('Puerto origen')
plt.subplot2grid((3,2),(1,0))
datos[datos['Tipo']==0]['Fwd Pkt Len Mean'].plot(kind='kde')
datos[datos['Tipo']==1]['Fwd Pkt Len Mean'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,300)
plt.title('Media tamaño paquetes Fwd')
plt.subplot2grid((3,2),(1,1))
datos[datos['Tipo']==0]['Bwd Pkt Len Mean'].plot(kind='kde')
datos[datos['Tipo']==1]['Bwd Pkt Len Mean'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,500)
plt.title('Media tamaño paquetes Bwd')
plt.subplot2grid((3,2),(2,0))
datos[datos['Tipo']==0]['Flow Pkts/s'].plot(kind='kde')
datos[datos['Tipo']==1]['Flow Pkts/s'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,250000)
plt.title('Paquetes por segundo do flow')
plt.subplot2grid((3,2),(2,1))
datos[datos['Tipo']==0]['Flow Byts/s'].plot(kind='kde')
datos[datos['Tipo']==1]['Flow Byts/s'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,100000)
plt.title('Bytes por segundo do flow')


# In[23]:


fig = plt.figure(figsize=(14,14))
plt.subplot2grid((3,2),(0,0))
datos[datos['Tipo']==0]['Flow IAT Mean'].plot(kind='kde')
datos[datos['Tipo']==1]['Flow IAT Mean'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,900000)
plt.title('Media tempo entre dous paquetes')
plt.subplot2grid((3,2),(0,1))
datos[datos['Tipo']==0]['Fwd IAT Mean'].plot(kind='kde')
datos[datos['Tipo']==1]['Fwd IAT Mean'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,600000)
plt.title('Media tempo entre dous paquetes Fwd')
plt.subplot2grid((3,2),(1,0))
datos[datos['Tipo']==0]['Bwd IAT Mean'].plot(kind='kde')
datos[datos['Tipo']==1]['Bwd IAT Mean'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,900000)
plt.title('Media tempo entre dous paquetes Bwd')
plt.subplot2grid((3,2),(1,1))
datos[datos['Tipo']==0]['Pkt Len Mean'].plot(kind='kde')
datos[datos['Tipo']==1]['Pkt Len Mean'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,400)
plt.title('Media do tamaño dos paquetes')
plt.subplot2grid((3,2),(2,0))
datos[datos['Tipo']==0]['Down/Up Ratio'].plot(kind='kde')
datos[datos['Tipo']==1]['Down/Up Ratio'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,4)
plt.title('Ratio subida e descarga')
plt.subplot2grid((3,2),(2,1))
datos[datos['Tipo']==0]['Pkt Size Avg'].plot(kind='kde')
datos[datos['Tipo']==1]['Pkt Size Avg'].plot(kind='kde')
plt.legend(('Normal','Ataque'))
plt.xlim(0,400)
plt.title('Tamaño medio dos paquetes')


# ### Creación de novas variables y OneHot Encoding

# Tras ver e analizar os datos dos que dispoñemos podemos ver que certas columnas non son compatibles co que queremos facer cos datos. Isto débese a que as columnas de tipo object e category non as vai a usar o algoritmo para realizar a clasificación dos datos, xa que só se usan as columnas que conteñen floats e ints. 
# Primeiro vamos a crear unhas novas variables para os puertos orixen e destino, xa que como o número de portos é moi elevado preferimos agrupar certos portos para non sobreentrenalo modelo.

# In[24]:


def crearPuertos(fila):
    #src = fila['Src Port']
    if fila == 0:
        return 0
    elif fila == 80:
        return 1
    elif fila == 53:
        return 2
    elif fila == 443:
        return 3
    elif fila == 137:
        return 4
    elif fila == 138:
        return 5
    elif fila == 3306:
        return 6
    elif fila < 1024:
        return 7
    elif fila >= 1024 and fila < 49152:
        return 8
    else:
        return 9
datos['Puerto Origen'] = datos['Src Port'].apply(crearPuertos)
datos['Puerto Destino'] = datos['Dst Port'].apply(crearPuertos)


# O seguinte que vamos a crear e coas Ips. Neste caso vamos a agrupar según a nosa topoloxía de rede, e deixando o resto de Ips noutro grupo.
# 192.168.8.128 = Controlador de Open Flow
# 192.168.8.129 = OVS Switch ens39
# 192.168.3.129 y 200.175.2.129 = Bridges Switch
# 172.17.0.1 = Docker
# 192.168.20.129 = Bridge Mininet
# 192.168.3.130 = Meta Server
# 200.175.2.130 = Máquina atacante
# 192.168.20.131-134 = Hosts Mininet

# In[25]:


def crearIP(fila):
    if fila == '172.17.0.1':
        return 0
    elif fila.startswith('192.168.8.'):
        return 1
    elif fila.startswith('192.168.3.'):
        return 2
    elif fila.startswith('200.175.2.'):
        return 3
    elif fila.startswith('192.168.20.'):
        return 4
    else:
        return 5
datos['IP Origen'] = datos['Src IP'].apply(crearIP)
datos['IP Destino'] = datos['Dst IP'].apply(crearIP)


# In[26]:


datos.head(10)


# In[27]:


#import sys
#import numpy
#numpy.set_printoptions(threshold=sys.maxsize)
#print(datos['Dst Port'].unique())
print(datos['Src IP'].value_counts())


# In[28]:


import numpy as np
datos['Timestamp'] = pd.to_datetime(datos['Timestamp'])
datos['Hora'] = datos['Timestamp'].dt.hour
datos['Seno Hora'] = np.sin(2.*np.pi*datos['Hora']/24.)
datos['Coseno Hora'] = np.cos(2.*np.pi*datos['Hora']/24.)


# ### Importancia dos predictores 

# Para ver a importancia de cada atributo vamos a crear un árbol de clasificación que nos vai decir cales son os atributos que máis inflúen a hora de clasificar os datos según o atributo Tipo.
# Ademáis antes vamos a eliminar certas columnas que non nos serán de utilidade a hora de clasificar o tráfico, xa que algunhas como a ip de destino ou orixen son descriptivas, así como o timestamp por exemplo.

# In[29]:


datos = datos.drop(['Flow ID','Src IP','Dst IP','Timestamp','Label'], axis=1)
datos.shape


# In[30]:


# from sklearn.compose import ColumnTransformer
# from sklearn.preprocessing import OneHotEncoder
# import numpy as np
# cat_cols = datost.select_dtypes(include=['object','category']).columns.to_list()
# num_cols = datost.select_dtypes(include=['float64','int64']).columns.to_list()
# preprocessor = ColumnTransformer([('onehot', OneHotEncoder(handle_unknown='ignore'), cat_cols)],remainder='passthrough')
# datosohe = preprocessor.fit_transform(datost)
# datosohe.shape


# In[31]:


from sklearn.ensemble import RandomForestClassifier
rng = np.random.RandomState(1)
modeloimportancia = RandomForestClassifier(n_estimators=100, bootstrap = True, verbose=2,max_features = 'sqrt', random_state=rng)
modeloimportancia = modeloimportancia.fit(datos,datos['Tipo'])
importancia = modeloimportancia.feature_importances_
for i,v in enumerate(importancia):
	print('Feature: '+datos.columns.values[i]+' , Score: %.5f' % (v))
plt.bar([x for x in range(len(importancia))], importancia)
plt.show()


# In[32]:


import seaborn as sns
corr = datos.corr()
positiva = corr[corr>=.9]
plt.figure(figsize=(20,20))
sns.heatmap(positiva, cmap="Greens", linewidths=.5, linecolor="black")


# In[33]:


corr = datos.corr()
negativa = corr[corr<=-0.4]
plt.figure(figsize=(20,20))
sns.heatmap(negativa, cmap="Greens", linewidths=.5, linecolor="black")


# In[34]:


datos = datos.drop(['Src Port','Dst Port','Hora','Fwd PSH Flags','Fwd URG Flags','Bwd PSH Flags','Bwd URG Flags','FIN Flag Cnt','SYN Flag Cnt','RST Flag Cnt','PSH Flag Cnt','ACK Flag Cnt',
'URG Flag Cnt','CWE Flag Count','ECE Flag Cnt','Fwd Byts/b Avg','Fwd Pkts/b Avg','Fwd Blk Rate Avg','Bwd Byts/b Avg','Bwd Pkts/b Avg','Bwd Blk Rate Avg','Init Fwd Win Byts',
'Fwd Seg Size Min','Subflow Fwd Byts','Subflow Bwd Byts','Subflow Fwd Pkts','Subflow Bwd Pkts','Fwd Pkt Len Mean','Bwd Pkt Len Mean','Bwd Pkts/s',
'Pkt Size Avg','Idle Max','Idle Min','Idle Mean','Flow IAT Std','Flow IAT Max','Bwd Pkt Len Max'], axis=1)


# In[35]:


datos.shape


# # Data Preparation
# ### Eliminación de outliers

# Para hacer este paso se usará Isolation Forest

# In[36]:


from sklearn.ensemble import IsolationForest
fig = plt.figure(figsize=(14,14))
plt.subplot2grid((1,2),(0,0))
plt.boxplot(datos["Tot Fwd Pkts"])
plt.title("Antes de aplicar IsolationForest",fontsize=25)
plt.xlabel("Tot Fwd Pkts", fontsize=18)
modeloisolation = IsolationForest(n_estimators = 100, max_samples ='auto', contamination = 0.0001, n_jobs = -1, random_state=rng)
modeloisolation.fit(datos[["Tot Fwd Pkts"]])
datos.shape
clasificacion_predicha = modeloisolation.predict(datos[["Tot Fwd Pkts"]])
datos['anomalias'] = clasificacion_predicha
score_anomalia = modeloisolation.decision_function(datos[["Tot Fwd Pkts"]])
datos['scores'] = score_anomalia
datos = datos.loc[(clasificacion_predicha != -1), :]
plt.subplot2grid((1,2),(0,1))
plt.boxplot(datos["Tot Fwd Pkts"])
plt.title("Después de aplicar IsolationForest",fontsize=25)
plt.xlabel("Tot Fwd Pkts", fontsize=18)


# In[37]:


datos.loc[datos['anomalias']==-1].head(500)


# In[38]:


fig = plt.figure(figsize=(14,14))
plt.subplot2grid((1,2),(0,0))
plt.boxplot(datos["TotLen Fwd Pkts"])
plt.title("Antes de aplicar IsolationForest",fontsize=25)
plt.xlabel("TotLen Fwd Pkts", fontsize=18)
modeloisolation.fit(datos[["TotLen Fwd Pkts"]])
datos.shape
clasificacion_predicha = modeloisolation.predict(datos[["TotLen Fwd Pkts"]])
datos['anomalias'] = clasificacion_predicha
score_anomalia = modeloisolation.decision_function(datos[["TotLen Fwd Pkts"]])
datos['scores'] = score_anomalia
datos = datos.loc[(clasificacion_predicha != -1), :]
plt.subplot2grid((1,2),(0,1))
plt.boxplot(datos["TotLen Fwd Pkts"])
plt.title("Después de aplicar IsolationForest",fontsize=25)
plt.xlabel("TotLen Fwd Pkts", fontsize=18)


# In[39]:


fig = plt.figure(figsize=(14,14))
plt.subplot2grid((1,2),(0,0))
plt.boxplot(datos["TotLen Bwd Pkts"])
plt.title("Antes de aplicar IsolationForest",fontsize=25)
plt.xlabel("TotLen Bwd Pkts", fontsize=18)
modeloisolation.fit(datos[["TotLen Bwd Pkts"]])
datos.shape
clasificacion_predicha = modeloisolation.predict(datos[["TotLen Bwd Pkts"]])
datos['anomalias'] = clasificacion_predicha
score_anomalia = modeloisolation.decision_function(datos[["TotLen Bwd Pkts"]])
datos['scores'] = score_anomalia
datos = datos.loc[(clasificacion_predicha != -1), :]
plt.subplot2grid((1,2),(0,1))
plt.boxplot(datos["TotLen Bwd Pkts"])
plt.title("Después de aplicar IsolationForest",fontsize=25)
plt.xlabel("TotLen Bwd Pkts", fontsize=18)


# In[40]:


fig = plt.figure(figsize=(14,14))
plt.subplot2grid((1,2),(0,0))
plt.boxplot(datos["Bwd Header Len"])
plt.title("Antes de aplicar IsolationForest",fontsize=25)
plt.xlabel("Bwd Header Len", fontsize=18)
modeloisolation.fit(datos[["Bwd Header Len"]])
datos.shape
clasificacion_predicha = modeloisolation.predict(datos[["Bwd Header Len"]])
datos['anomalias'] = clasificacion_predicha
score_anomalia = modeloisolation.decision_function(datos[["Bwd Header Len"]])
datos['scores'] = score_anomalia
datos = datos.loc[(clasificacion_predicha != -1), :]
plt.subplot2grid((1,2),(0,1))
plt.boxplot(datos["Bwd Header Len"])
plt.title("Después de aplicar IsolationForest",fontsize=25)
plt.xlabel("Bwd Header Len", fontsize=18)


# In[41]:


datos.shape


# ### Transformación de datos

# Consta de tres pasos, normalización, estandarización de las caraterísticas y creación de nuevas características.
# Empezaremos por realizar la 

# Seguimos con la estandarización

# In[42]:


from sklearn import preprocessing
scaler = preprocessing.StandardScaler().fit(datos)
scaled = scaler.transform(datos)
scaled.mean(axis=0)


# También vamos a realizar la selección de características, para lo que vamos a usar el algoritmo RFECV

# In[43]:


from sklearn.feature_selection import RFECV
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import StratifiedKFold
rng = np.random.RandomState(10)
Xrfecv = datos.drop(['Tipo','anomalias','scores'], axis=1)
yrfecv = datos['Tipo']
rfecv = RFECV(estimator=DecisionTreeClassifier(max_depth=None,random_state=rng), step=1, cv=StratifiedKFold(n_splits=5,shuffle=True,random_state=rng), scoring='accuracy', n_jobs=-1)
rfecv.fit(Xrfecv,yrfecv)


# In[44]:


print("Optimum number of features: %d" % rfecv.n_features_)
plt.figure(figsize=(16,6))
plt.title('Total features selected versus accuracy')
plt.xlabel('Total features selected')
plt.ylabel('Model accuracy')
plt.plot(range(1, len(rfecv.grid_scores_) + 1), rfecv.grid_scores_)
plt.show()


# In[45]:


df_features = pd.DataFrame(columns = ['feature', 'support', 'ranking'])

for i in range(Xrfecv.shape[1]):
    row = {'feature': Xrfecv.columns.values[i], 'support': rfecv.support_[i], 'ranking': rfecv.ranking_[i]}
    df_features = df_features.append(row, ignore_index=True)
    
df_features.sort_values(by='ranking').head(60)
df_features[df_features['support']==True]


# Finally, to extract the selected features and use them as the model features in X you can run the get_support() function and pass in an argument of 1 to return all of the items with support.

# In[46]:


selected_features = rfecv.get_support(1)
X = datos[datos.columns[selected_features]]
X.shape


# In[47]:


X.head(5)


# ### Modelado

# Vamos a evaluar los tres modelos mediante validación cruzada

# In[48]:


X = datos.sample(100)
Xprueba = X.drop(['Tipo','anomalias','scores'], axis=1)
yprueba = X['Tipo']


# In[49]:


from sklearn.model_selection import train_test_split
from sklearn.model_selection import StratifiedKFold
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import cross_val_score
from sklearn.metrics import accuracy_score
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.metrics import confusion_matrix
from numpy import mean
from numpy import std
cv_externo = StratifiedKFold(n_splits=5, shuffle=True, random_state=rng)
cv_interno = StratifiedKFold(n_splits=3, shuffle=True, random_state=rng)
outer_results = list()
models = []
models.append(('LR',LogisticRegression(max_iter=1000000, random_state=rng),{"C": [1,10,100], "tol": [0.0001,0.001,0.01], "penalty": ['l2','none']}))
models.append(('RF',RandomForestClassifier(random_state=rng),{"n_estimators": [50,100,150,200], "max_depth": [3,5,7,9], "n_jobs": [-1]}))
models.append(('SVM',LinearSVC(max_iter=1000000, random_state=rng),{"C": [1,10,100], "tol": [0.0001,0.001,0.01]}))
cvresultslr = []
cvresultsrf = []
cvresultssvm = []
names = []
for name, model, param in models:
   for train_ix, test_ix in cv_externo.split(Xprueba,yprueba):
      x_train, x_test = Xprueba.iloc[train_ix, :], Xprueba.iloc[test_ix, :]
      y_train, y_test = yprueba.iloc[train_ix], yprueba.iloc[test_ix]
      gs = GridSearchCV(model,param,scoring='accuracy',cv=cv_interno, refit=True, verbose=5)
      result = gs.fit(x_train, y_train)
      print("Best cross-validation accuracy: {:.12f}".format(result.best_score_))
      print("Test set score: {:.12f}".format(result.score(x_test, y_test)))
      print("Best parameters: {}".format(result.best_params_))
      if name == 'LR':
         cvresultslr.append(pd.DataFrame(result.cv_results_))
      elif name == 'RF':
         cvresultsrf.append(pd.DataFrame(result.cv_results_))
      elif name == 'SVM':
         cvresultssvm.append(pd.DataFrame(result.cv_results_)) 
   #scores = cross_val_score(busqueda,Xprueba,yprueba,scoring='accuracy',cv=cv_externo,n_jobs=-1)
   best_model = result.best_estimator_
   y_pred = best_model.predict(x_test)
   # cm = confusion_matrix(y_test,y_pred)
   # fig, ax = plt.subplots(figsize=(10,5))
   # ax.matshow(cm)
   # plt.title('Matriz de Confusión', fontsize=20)
   # plt.ylabel('Etiqueta Verdadera', fontsize=15)
   # plt.xlabel('Etiqueta Predicha', fontsize=15)
   # for (i, j), z in np.ndenumerate(cm):
   #    ax.text(j, i, '{:d}'.format(z), ha='center', va='center')
   # plt.show()
   acc = accuracy_score(y_test, y_pred)
   outer_results.append(acc)
   #results.append(outer_results)
   names.append(name)
   print('>acc=%.3f, best=%.3f, cfg=%s' % (acc, result.best_score_, result.best_params_))
   print("Accuracy: %s: %f (%f)" % (name, mean(outer_results), std(outer_results)))
	


# In[50]:


medialr = []
desviacionlr = []
tuplaslr = []
paramlr = []
i = 0
for df in cvresultslr:
    i = i+1
    for j in df.index:
        if i == 1:
            medialr.append(df.loc[j,'mean_test_score'])
            desviacionlr.append(df.loc[j,'std_test_score'])
            paramlr.append((j,df.loc[j,'params']))
        else:
            medialr[j] = medialr[j] + df.loc[j,'mean_test_score']
            desviacionlr[j] = desviacionlr[j] + df.loc[j,'std_test_score']
i = 0
for n in medialr:
    medialr[i] = n/5
    i = i+1
i = 0
for n in desviacionlr:
    desviacionlr[i] = n/5
    i = i+1
i = 0
for n in medialr:
    tuplaslr.append((i,medialr[i]/desviacionlr[i]))
    i = i+1
tuplaslr = sorted(tuplaslr, key=lambda result : result[1], reverse=True)
print(tuplaslr)
print(paramlr)


# In[51]:


import pickle
from sklearn import model_selection
X_train, X_test, Y_train, Y_test = model_selection.train_test_split(Xprueba, yprueba, test_size=0.3, random_state=rng)
parametroslr= paramlr[tuplaslr[0][0]][1]
penaltyl = parametroslr['penalty']
Cl = parametroslr['C']
toll = parametroslr['tol']
modelolr = LogisticRegression(C=Cl, tol=toll, penalty=penaltyl)
modelolr.fit(X_train,Y_train)
filelr = 'modelolr.sav'
pickle.dump(modelolr,open(filelr,'wb'))
y_pred = modelolr.predict(X_test)
cm = confusion_matrix(Y_test,y_pred)
fig, ax = plt.subplots(figsize=(10,5))
ax.matshow(cm)
plt.title('Matriz de Confusión', fontsize=20)
plt.ylabel('Etiqueta Verdadera', fontsize=15)
plt.xlabel('Etiqueta Predicha', fontsize=15)
for (i, j), z in np.ndenumerate(cm):
    ax.text(j, i, '{:d}'.format(z), ha='center', va='center')
plt.show()


# In[52]:


mediarf = []
desviacionrf = []
tuplasrf = []
paramrf = []
i = 0
for df in cvresultsrf:
    i = i+1
    for j in df.index:
        if i == 1:
            mediarf.append(df.loc[j,'mean_test_score'])
            desviacionrf.append(df.loc[j,'std_test_score'])
            paramrf.append((j,df.loc[j,'params']))
        else:
            mediarf[j] = mediarf[j] + df.loc[j,'mean_test_score']
            desviacionrf[j] = desviacionrf[j] + df.loc[j,'std_test_score']
i = 0
for n in mediarf:
    mediarf[i] = n/5
    i = i+1
i = 0
for n in desviacionrf:
    desviacionrf[i] = n/5
    i = i+1
i = 0
for n in mediarf:
    tuplasrf.append((i,mediarf[i]/desviacionrf[i]))
    i = i+1
tuplasrf = sorted(tuplasrf, key=lambda result : result[1], reverse=True)
print(tuplasrf)
print(paramrf)


# In[53]:


parametrosrf= paramrf[tuplasrf[0][0]][1]
depth = parametrosrf['max_depth']
estimators = parametrosrf['n_estimators']
jobs = parametrosrf['n_jobs']
modelorf = RandomForestClassifier(max_depth=depth, n_estimators=estimators, n_jobs=jobs)
modelorf.fit(X_train,Y_train)
filerf = 'modelorf.sav'
pickle.dump(modelorf,open(filerf,'wb'))
y_pred = modelorf.predict(X_test)
cm = confusion_matrix(Y_test,y_pred)
fig, ax = plt.subplots(figsize=(10,5))
ax.matshow(cm)
plt.title('Matriz de Confusión', fontsize=20)
plt.ylabel('Etiqueta Verdadera', fontsize=15)
plt.xlabel('Etiqueta Predicha', fontsize=15)
for (i, j), z in np.ndenumerate(cm):
    ax.text(j, i, '{:d}'.format(z), ha='center', va='center')
plt.show()


# In[54]:


mediasvm = []
desviacionsvm = []
tuplassvm = []
paramsvm = []
i = 0
for df in cvresultssvm:
    i = i+1
    for j in df.index:
        if i == 1:
            mediasvm.append(df.loc[j,'mean_test_score'])
            desviacionsvm.append(df.loc[j,'std_test_score'])
            paramsvm.append((j,df.loc[j,'params']))
        else:
            mediasvm[j] = mediasvm[j] + df.loc[j,'mean_test_score']
            desviacionsvm[j] = desviacionsvm[j] + df.loc[j,'std_test_score']
i = 0
for n in mediasvm:
    mediasvm[i] = n/5
    i = i+1
i = 0
for n in desviacionsvm:
    desviacionsvm[i] = n/5
    i = i+1
i = 0
for n in mediasvm:
    tuplassvm.append((i,mediasvm[i]/desviacionsvm[i]))
    i = i+1
tuplassvm = sorted(tuplassvm, key=lambda result : result[1], reverse=True)
print(tuplassvm)
print(paramsvm)


# In[55]:


parametrossvm= paramsvm[tuplassvm[0][0]][1]
Cs = parametrossvm['C']
tols = parametrossvm['tol']
modelosvm = LinearSVC(C=Cs, tol=tols)
modelosvm.fit(X_train,Y_train)
filesvm = 'modelosvm.sav'
pickle.dump(modelosvm,open(filesvm,'wb'))
y_pred = modelosvm.predict(X_test)
cm = confusion_matrix(Y_test,y_pred)
fig, ax = plt.subplots(figsize=(10,5))
ax.matshow(cm)
plt.title('Matriz de Confusión', fontsize=20)
plt.ylabel('Etiqueta Verdadera', fontsize=15)
plt.xlabel('Etiqueta Predicha', fontsize=15)
for (i, j), z in np.ndenumerate(cm):
    ax.text(j, i, '{:d}'.format(z), ha='center', va='center')
plt.show()

