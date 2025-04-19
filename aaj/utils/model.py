import logging
import joblib
import datasets
import pickle
import csv
import mlflow.data
from mlflow.data.pandas_dataset import PandasDataset
from abc import ABC, abstractmethod
from fil.settings import MODELS_ADDRESS, DATASET_ADDRESS 
from mlflow.models.signature import ModelSignature, Schema

logger = logging.getLogger("ip_classification.main")

class Model(ABC,mlflow.pyfunc.PythonModel):
    
    def __init__(self, model_name='model',  payload=0, payload_name='default'):
        self.name = model_name
        self.payload = payload
        self.payload_name = payload_name
        self.model_obj = None
        self.report = None
    
    @abstractmethod
    def preprocess(self):
        pass 

    @abstractmethod
    def train(self):
        pass

    @abstractmethod
    def predict(self,context=None, model_input=None, params=None):
        # preprocess 
        # self.model_obj.predict(X)
        pass

    def save_model_fil(self):
        joblib.dump(self, f"{MODELS_ADDRESS}{self.__str__()}.joblib")

    def load_dataset_from_fil(self):
        return [pickle.loads(data['labeled_data']) for data in datasets.load_from_disk(dataset_path=DATASET_ADDRESS)]

    def generate_mlflow_options(self, df):
        
        dataset: PandasDataset = mlflow.data.from_pandas(df)

        metric_dict = {}
        for payload, report in self.report.items():
            if str(payload).isdigit():
                for metric, value in report.items():
                    metric_dict[f"{payload}_{metric}"] = value

        dict_feature = self.feature_importances if self.feature_importances else dict(sorted(zip(self.model_obj.feature_names, self.model_obj.feature_importances_), key=lambda x: x[1], reverse=True))
        TMP_CSV_FILE_NAME = 'mycsvfile.csv'
        with open(TMP_CSV_FILE_NAME,'w') as f:
            w = csv.writer(f)
            w.writerow(dict_feature.keys())
            w.writerow(dict_feature.values())

        # input_schema  = Schema([{'name': 'ipmeta1', 'type': 'python_object'}, {'name': 'ipmeta2', 'type': 'python_object'}])
        # output_schema = Schema({'type': 'double'})
        # params_schema = Schema([{'name': 'params', 'type': 'map', 'keytype': 'string', 'valuetype': 'string'}])
        
        return dataset, metric_dict, TMP_CSV_FILE_NAME#, ModelSignature(inputs=input_schema, outputs=output_schema, params=params_schema)
    
    def __str__(self):
        return f"{self.name}_{self.payload_name}"
