import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
pd.options.display.max_rows = None
pd.options.display.max_columns = None
ficherogrupo1 = 'Normal_data.csv'
benigno = pd.read_csv(ficherogrupo1, header=0)
ficherogrupo2 = 'metasploitable-2.csv'
meta = pd.read_csv(ficherogrupo2, header=0)
ficherogrupo3 = 'OVS.csv'
ovs = pd.read_csv(ficherogrupo3, header=0)
benigno = benigno.assign(Tipo = 0)
meta = meta.assign(Tipo = 1)
ovs = ovs.assign(Tipo = 1)
datos = pd.concat([benigno, meta, ovs])
cat_cols = datos.select_dtypes(include=['object','category']).columns.to_list()
num_cols = datos.select_dtypes(include=['float64','int64']).columns.to_list()
preprocessor = ColumnTransformer([('onehot', OneHotEncoder(handle_unknown='ignore'), cat_cols)],remainder='passthrough')
datosohe = preprocessor.fit_transform(datos)
datosohe.shape