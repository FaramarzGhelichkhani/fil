import logging
import datetime
import pandas
import logging
import os
import numpy as np 
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from aaj.utils.preparing import Preparation

from utils.ipmeta.main import check_ipmeta_completion
from utils.mlflow_handler import MlflowHandeler
from aaj.utils.similarity import Similarity, FastSimilairty
from aaj.utils.model import Model
from aaj.models import IntelligentModel

logger = logging.getLogger("ip_classification.main")

class RandomForestSimilarity(Model):             
    
    def __init__(self, name="model", payload="fil"):
        super(RandomForestSimilarity, self).__init__(name, payload)
    
    def preprocess(self, dataset):
        prepare_obj = Preparation(dataset)
        #prepare_obj.empty_ipmeta_drop()
        
        #base_time = "2024-03-27 00:00:00"
        #base_format = "%Y-%m-%d %H:%M:%S"
        #prepare_obj.set_time(base_time, base_format)
        
        payload_drop_list = [27459, 28392]
        prepare_obj.payload_drop(payload_drop_list)
        
        prepare_obj.duplicate_ip_drop()
        
        prepare_obj.sampling_payloads()
        
        path = "/var/fil/data/vpn_payload.csv"
        prepare_obj.paired_ipmeta(path)
        
        self.df = prepare_obj.calculate_df_similarity()
        logger.info(f"finish preprocessing dataset: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        return self.df
    
    def get_params(self):
        """"To return hyperparameters."""
        return self.model_obj.get_params()

    def calculate_conditions(self, df):
        df["min_condition"] = df.apply(lambda x : 1 if \
                               x["port_percent_weighted_similarity"]     > 0.01 and
                               x["domain_percent_weighted_similarity"]   > 0.01 and
                               x["dns_percent_weighted_similarity"]      > 0.01 and 
                               x["appid_percent_weighted_similarity"]    > 0.0
                               else 0, axis =1 )
        
        df["condition"] = df.apply(lambda x : 1 if \
                                x["port_percent_weighted_similarity"]     > 0.01 and
                                x["port_percent_similarity"]              > 0.3 and
                                x['port_drop_default_value_ratio']        > 0.0 and                           
                                x["port_number_ratio"]                    > 0.1 and                                                
                                
                                x["domain_percent_weighted_similarity"]   > 0.1 and
                                x["domain_percent_similarity"]            > 0.3 and
                                x["domain_drop_default_value_ratio"]      > 0.0 and
                                x["domain_number_ratio"]                  > 0.1 and
                                
                                x["dns_percent_weighted_similarity"]      > 0.01 and
                                x["dns_percent_similarity"]               > 0.3  and
                                x["dns_number_ratio"]                     > 0.01 and
                                x["appid_percent_similarity"]             > 0.0 and
                                x["appid_drop_default_value_ratio"]       > 0.0 and
                                x["appid_percent_weighted_similarity"]    > 0.0 and

                                x["L4_dist_percent_similarity"]           > 0.0 and
                                x["L7_dist_percent_similarity"]           > 0.0 
                                else 0, axis =1)

        true_df = df.query("condition == 1")
        false_df= df.query("condition == 0")
        df = pd.concat([false_df.sample(n=int(1.0*true_df.shape[0])), true_df.sample(frac=1)])                                
        
        return df
    
    def train(self, dataset, feature_names=False, **kwargs):
        

        if len(kwargs.keys())==0:
            kwargs = {'bootstrap': True,
                      'ccp_alpha': 0.0,
                      'class_weight': None,
                      'criterion': 'entropy',
                      'max_depth': 15,
                      'max_features': 'sqrt',
                      'max_leaf_nodes': None,
                      'max_samples': None,
                      'min_impurity_decrease': 0.0,
                      'min_samples_leaf': 100,
                      'min_samples_split': 1000,
                      'min_weight_fraction_leaf': 0.0,
                      'n_estimators': 20,
                      'n_jobs': None,
                      'oob_score': False,
                      'random_state': 242,
                      'verbose': 0,
                      'warm_start': False}
        
        df = self.preprocess(dataset=dataset)
        df = self.calculate_conditions(df)
        self.df = df
        if feature_names == False:
            feature_names = self.df.columns.to_list()[:40]
        
        X_train, X_test, y_train, y_test = train_test_split(df[feature_names].values, df['condition'], test_size=0.3, random_state=42)
      
        rf = RandomForestClassifier(**kwargs)
        rf.feature_names = feature_names

        rf.fit(X_train, y_train)
        logger.info(f"finish training model: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        y_pred = rf.predict(X_test)
        self.report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        logger.info(f"finish classification report model: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.model_obj = rf
        self.feature_importances = False


    def paired_dataset(self, dataset):
        paired_list = []
        for i in range(len(dataset)):
            for j in range(i+1, len(dataset)):
                paired_list.append([dataset[i], dataset[j]])
        return paired_list
        
    def predict(self, context, model_input, params=None):

        ipmeta1 = model_input['ipmeta1']
        ipmeta2 = model_input['ipmeta2']
        fast = model_input['fast']
        prob_flag = model_input['prob_flag']
        if fast:
            sim = FastSimilairty.ip(ipmeta1, ipmeta2)[1]
            if sim is None:
                sim = {'port_percent_weighted_similarity': 0.0, 'port_number_ratio': 0.0, 'domain_percent_weighted_similarity': 0.0, 
                 'domain_number_ratio': 0.0, 'dns_percent_weighted_similarity': 0.0, 'dns_number_ratio': 0.0,
                 'appid_percent_weighted_similarity': 0.0, 'appid_number_ratio': 0.0, 'L4_dist_percent_weighted_similarity': 0.0,
                 'L4_dist_number_ratio': 0.0, 'L7_dist_percent_weighted_similarity': 0.0, 'L7_dist_number_ratio': 0.0,
                 'port_percent_similarity': 0.0, 'port_drop_default_value_ratio': 0.0, 'port_traffic_ratio': 0.0,
                 'port_sub_ratio': None, 'domain_percent_similarity': 0.0, 'domain_drop_default_value_ratio': 0.0, 
                 'domain_traffic_ratio': 0.0, 'domain_sub_ratio': 0.0, 'dns_percent_similarity': 0.0, 'dns_drop_default_value_ratio': 0.0,
                 'dns_traffic_ratio': 0.0, 'dns_sub_ratio': 0.0, 'appid_percent_similarity': 0.0, 'appid_drop_default_value_ratio': 0.0,
                 'appid_traffic_ratio': 0.0, 'appid_sub_ratio': None, 'L4_dist_percent_similarity': 0.0, 
                 'L4_dist_drop_default_value_ratio': 0.0, 'L4_dist_traffic_ratio': 0.0, 'L4_dist_sub_ratio': None, 
                 'L7_dist_percent_similarity': 0.0, 'L7_dist_drop_default_value_ratio': 0.0, 'L7_dist_traffic_ratio': 0.0,
                 'L7_dist_sub_ratio': None, 'asn': 0.0, 'total_traffic_ratio': 0.0, 'totalbcs_ratio': 0.0, 'totalbsc_ratio': 0.0,
                 'bsc_bcs_ratio': 0.0, 'bcs_hit_ratio': 0.0, 'bsc_hit_ratio': 0.0, 'ip_number_ratio': 0.0}
        else:
            sim = Similarity.ip(ipmeta1, ipmeta2)

        vector = np.array([sim[key] for key in self.model_obj.feature_names])

        if prob_flag:
            y_pred = self.model_obj.predict_proba(vector.reshape(1, -1)).tolist()[0][1]
        else:
            y_pred = self.model_obj.predict(vector.reshape(1, -1)).tolist()[0] 
            
        return y_pred