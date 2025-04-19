import random
import pandas as pd 
import xgboost as xgb
import numpy as np
from aaj.utils.model import Model
from aaj.utils.preparing import get_sni
from collections import defaultdict
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

class Process():
    
    def __init__(self, dataset, payload, key_number=40, key_number_payloloadset=10, seed=42, **kwargs):
        self.dataset = dataset
        self.payload = payload
        self.key_number = key_number
        self.key_number_payloloadset=key_number_payloloadset
        self.seed = seed
        self.as_threshold = kwargs.get("ASN_THRESHOLD", 0.9)
        self.min_as_sample = kwargs.get("MIN_ASN_SAMPLE", 15)
        self.min_target_sample = kwargs.get("MIN_TARGET_SAMPLE", 100)
        random.seed(self.seed)
    
    @classmethod
    def _create_dict_keys(cls, data, sample_number):
        """
        return dictionary feature key: number of sample
        """
        ports= {}
        asns = {}
        doms = {}
        for row in data:
            ipmeta = row
            for portdist in ipmeta.port_dist:
                ports.setdefault(portdist.port,0)
                ports[portdist.port] += 1 
            for domdist in ipmeta.domain_dist:
                doms.setdefault(domdist.domain,0)
                doms[domdist.domain] += 1 
            asns.setdefault(ipmeta.asn,0)
            asns[ipmeta.asn] +=1
        port_   = ['port_'+ str(row[0]) for row in sorted(ports.items(), key=lambda r : r[1], reverse=True)[:sample_number]]
        domain_ = [row[0] for row in sorted(doms.items(), key=lambda r : r[1], reverse=True)[:sample_number]]
        asn_    = ['as_' + str(row[0]) for row in sorted(asns.items(), key=lambda r : r[1], reverse=True)[:sample_number]]

        return port_, domain_, asn_      
    
    def _sample_asn(self, data, threshold=0.9):
        asns = {}
        asn_ips = {}
        for ipmeta in data:
            asns.setdefault(ipmeta.asn,0)
            asns[ipmeta.asn] +=1
            asn_ips.setdefault(ipmeta.asn,[]).append(ipmeta)
        
        cumulative_sum = 0 
        selected_keys = []
        for key, repetition in sorted(asns.items(), key=lambda r : r[1], reverse=True):
            if cumulative_sum > threshold or repetition < self.min_as_sample:
                break
            cumulative_sum += repetition/len(data)
            selected_keys.append(key)
        
        self.asn_keys_payload = selected_keys
        return [ip for key in selected_keys if key in asn_ips for ip in asn_ips[key] ]

    def _sample_dataset(self):
        true_dataset = []
        false_by_label = defaultdict(list)
        for row in self.dataset:
            ipmeta= row[0]
            label = int(row[1])
            if label == self.payload:
                true_dataset.append(ipmeta)
            else:
                false_by_label[label].append(ipmeta)
        
        false_dataset = []
        for label, items in false_by_label.items():
            sample_number=min(len(items), 10*len(true_dataset))
            false_dataset.extend(random.sample(items,k=sample_number))

        as_sample_true_dataset = self._sample_asn(data=true_dataset, threshold=self.as_threshold)
        if len(as_sample_true_dataset) < self.min_target_sample:
            raise ValueError(f"number of  instance less than {self.min_target_sample}")
        return as_sample_true_dataset, false_dataset    

    def _extract_key_features(self, other_dataset, payload_dataset ):
        """"
        considering keys from payload 
        maximum 50 key for port, asn, dns.
        """
        port_keys_all , domain_keys_all, asn_keys_all = self.__class__._create_dict_keys(other_dataset, self.key_number)         
        port_keys_payloas , domain_keys_payload, asn_keys_payload = self.__class__._create_dict_keys(payload_dataset, self.key_number_payloloadset)
        self.port_keys = list(set(port_keys_payloas) | set(port_keys_all)) 
        self.domain_keys = list(set(domain_keys_payload) | set(domain_keys_all)) 
        self.asn_keys = list(set(asn_keys_payload) | set(asn_keys_all)) 
       
    @classmethod
    def create_data(cls, data, port_keys, domain_keys, asn_keys):
        out = []
        for ipmeta in data:
            dict_row = {key: 0 for key in port_keys + domain_keys + asn_keys}
            dict_row["dns_resolved"] = int(len(ipmeta.dns_dist) > 0)
            dict_row = get_sni(ipmeta, dict_row)
            dict_row["ip"]=ipmeta.ip

            for portdist in ipmeta.port_dist:
                if 'port_' + str(portdist.port) in port_keys:
                    dict_row['port_' + str(portdist.port)]+= portdist.traffic
            for domaindist in ipmeta.domain_dist:
                if domaindist.domain in domain_keys:
                    dict_row[domaindist.domain]+= domaindist.traffic
            if 'as_' + str(ipmeta.asn) in asn_keys:
                dict_row['as_' + str(ipmeta.asn)]+= ipmeta.total_traffic         
            out.append(dict_row)       
        return out     

    def create_sample_df(self):
        true_dataset, false_dataset = self._sample_dataset()
        self._extract_key_features(false_dataset, true_dataset)
        true_instance_number = len(true_dataset)
        false_dataset_sample = random.sample(false_dataset, k=2*true_instance_number)

        false_data = self.__class__.create_data(false_dataset_sample, self.port_keys, self.domain_keys, self.asn_keys)
        true_data =  self.__class__.create_data(true_dataset, self.port_keys, self.domain_keys, self.asn_keys)
        true_df = pd.DataFrame(true_data)
        false_df = pd.DataFrame(false_data)
        true_df["tag"]  =1
        false_df["tag"] =0
        return  pd.concat([true_df, false_df], axis=0)


class XGBModel_Binary(Model):
    
    def __init__(self):
        super(XGBModel_Binary,self).__init__()

    def set_params(self):
        """"To set hyperparameters."""
        args = self.params
        params = {
                'objective': 'binary:logistic', 
                'max_depth': args.get("MAX_DEPTH",3),
                'subsample': args.get("SUBSAMPLE", 0.3),
                'eta': args.get("ETA",0.1),
                'eval_metric': args.get("EVAL_METRIC",'logloss'),
                'seed': args.get('seed',42),
                'early_stopping_rounds': args.get("EARLY_STOPPING_ROUNDS",3),
                'num_boost_round': args.get("NUM_BOOST_ROUND",10),

        }
        PROBABILITY_THERESHOLD =  args.get("PROBABILITY_THERESHOLD",0.9)
        self.threshold = PROBABILITY_THERESHOLD
        return params

    def get_params(self):
        """"To return hyperparameters."""
        self.params["payload_asns"] = self.payload_asns
        return self.params
    
    def preprocess(self, dataset, **kwargs):
        p = Process(dataset=dataset , payload=self.payload, **kwargs)
        self.df = p.create_sample_df()
        self.port_keys   = p.port_keys
        self.domain_keys = p.domain_keys
        self.asn_keys    = p.asn_keys
        self.payload_asns = p.asn_keys_payload

    def train(self, dataset, **kwargs):
        self.preprocess(dataset=dataset, **kwargs)
        X = self.df.drop(["ip","tag"], axis=1)
        y = self.df["tag"]
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.1, random_state=kwargs.get('seed',42))
        dtrain = xgb.DMatrix(X_train, label=y_train)
        dtest = xgb.DMatrix(X_test, label=y_test)
        evallist = [(dtrain, 'train'), (dtest, 'eval')]
        
        self.params = kwargs
        params= self.set_params()
        model = xgb.train(params, dtrain, params.pop("num_boost_round"), evals=evallist, early_stopping_rounds=params.pop("early_stopping_rounds") )
        y_pred_prob = model.predict(dtest)
        y_pred = np.where(y_pred_prob > self.threshold, 1, 0)
        self.report = classification_report(y_test, y_pred, output_dict=True, zero_division=0, target_names=[0, 1])
        self.feature_importances = model.get_score(importance_type='weight')
        self.model_obj = model
        self.feature_names = model.feature_names

    def predict(self, context=None, model_input={"ipmetas":[]}, params=None):
        if type(context) == dict:
            model_input = context
                     
        ipmetas= model_input["ipmetas"] # list of ipmetas
        threshold = model_input.get('threshold',self.threshold) 
        data = Process.create_data(ipmetas, self.port_keys, self.domain_keys, self.asn_keys)
        df = pd.DataFrame(data)
        x = df[self.feature_names]
        dtest = xgb.DMatrix(x)
        y_pred_prob = self.model_obj.predict(dtest)
        y_pred = np.where(y_pred_prob > threshold, 1, 0)
        
        for index , ip in enumerate(ipmetas):
            if ip.asn not in self.payload_asns:
                y_pred[index]=0

        return  y_pred
