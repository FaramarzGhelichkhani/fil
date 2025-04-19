import pandas as pd
import numpy as np
import logging
import json
from aaj.utils.model import Model
from khortum.models import Payload
from sklearn.metrics import classification_report
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.model_selection import GridSearchCV
from datetime import datetime
from utils.ipmeta.main import check_ipmeta_completion
logger = logging.getLogger("ip_classification.main")


def get_numeric_data(ipmeta):
    country = ipmeta.country
    asn_iran = 1 if country == 'Iran' else 0
    total_hit = ipmeta.totalhit
    bytes_ratio = (ipmeta.totalbsc / ipmeta.totalbcs) if ipmeta.totalbcs != 0 else 0
    hit_traffic_ratio = (ipmeta.totalbsc + ipmeta.totalbcs) / total_hit if total_hit != 0 else 0
    data = {'ip': ipmeta.ip, 'asn_iran': asn_iran, 'total_hit': total_hit, 'bytes_ratio': bytes_ratio,'hit_traffic_ratio': hit_traffic_ratio}
    return data


def create_data_ipmeta(ipmeta):
    try:
        data = get_numeric_data(ipmeta)
        data = dns_features_extractor(ipmeta, data)
        data = port_features_extractor(ipmeta, data)
        data = size_features_extractor(ipmeta, data)
        return data
    except Exception as e:
        logger.error(e, {"command":"train"})


def dns_features_extractor(ipmeta, data):
    count_host = len(ipmeta.dns_dist)
    percents = []
    hosts_length = []
    for dnsdist in ipmeta.dns_dist:
        host = dnsdist.dns
        percents.append(dnsdist.percent)
        hosts_length.append(len(host))

    if count_host > 0:
        mean_percent = np.mean(percents)
        variance_percent = np.var(percents)
        mean_length = np.mean(hosts_length)
        variance_length = np.var(hosts_length)
    else:
        mean_percent = 0
        variance_percent = 0
        mean_length = 0
        variance_length = 0

    data["count_dns"] = count_host
    data["dns_percent_mean"] = mean_percent
    data["dns_percent_var"] = variance_percent
    data["dns_length_mean"] = mean_length
    data["dns_length_var"] = variance_length

    return data


def size_features_extractor(ipmeta, data):
    ssl_sizes = []
    ssl_percent = []
    tcp_sizes = []
    tcp_percent = []
    udp_sizes = []
    udp_percent = []
    for sizedist in ipmeta.size_dist:
        if sizedist.protocol == 'ssl':
            ssl_sizes.append(int(sizedist.size))
            ssl_percent.append(sizedist.percent)
        elif sizedist.protocol == 'tcp':
            tcp_sizes.append(int(sizedist.size))
            tcp_percent.append(sizedist.percent)
        elif sizedist.protocol == 'udp':
            udp_sizes.append(int(sizedist.size))
            udp_percent.append(sizedist.percent)

    ssl_mean, ssl_var = 0, 0
    tcp_mean, tcp_var = 0, 0
    udp_mean, udp_var = 0, 0
    if len(ssl_sizes) > 0:
        ssl_mean = np.average(ssl_sizes, weights=ssl_percent)
        ssl_var = np.average((ssl_sizes - ssl_mean) ** 2, weights=ssl_percent)
    if len(tcp_sizes) > 0:
        tcp_mean = np.average(tcp_sizes, weights=tcp_percent)
        tcp_var = np.average((tcp_sizes - tcp_mean) ** 2, weights=tcp_percent)
    if len(udp_sizes) > 0:
        udp_mean = np.average(udp_sizes, weights=udp_percent)
        udp_var = np.average((udp_sizes - udp_mean) ** 2, weights=udp_percent)

    data["size_ssl_count"] = len(ssl_sizes)
    data["size_ssl_mean"] = ssl_mean
    data["size_ssl_var"] = ssl_var
    data["size_tcp_count"] = len(tcp_sizes)
    data["size_tcp_mean"] = tcp_mean
    data["size_tcp_var"] = tcp_var
    data["size_udp_count"] = len(udp_sizes)
    data["size_udp_mean"] = udp_mean
    data["size_udp_var"] = udp_var

    return data


def port_features_extractor(ipmeta, data):
    count_port = len(ipmeta.port_dist)
    none_default_port_percent = 0
    none_default_port_number = 0
    number_of_none_default_port = 0
    port443 = 0
    port80 = 0
    port53 = 0
    for portdist in ipmeta.port_dist:
        if portdist.port == 443:
            port443 = portdist.percent
        elif portdist.port == 80:
            port80 = portdist.percent
        elif portdist.port == 53:
            port53 = portdist.percent
        elif portdist.port > 1023:
            none_default_port_percent += portdist.percent
            number_of_none_default_port += 1

    data["count_port"] = count_port
    data["port443"] = port443
    data["port53"] = port53
    data["port80"] = port80
    data["none_default_port_number"] = none_default_port_number
    data["none_default_port_percent"]   =  none_default_port_percent

    return data


class MyRandomForestClassifier(RandomForestClassifier):
    def __init__(self, n_estimators=100, max_features='sqrt', max_depth=15, criterion='gini', random_state=42, min_samples_leaf=1, threshold=0.5):
        super().__init__(n_estimators=n_estimators, max_features=max_features, max_depth=max_depth, criterion=criterion,random_state=random_state, min_samples_leaf=min_samples_leaf)
        self.supported_apps = []
        self.threshold = threshold

    def predict(self, X):
        proba = self.predict_proba(X)
        predicted_classes = [self.classes_[p.argmax()] if p.max() >= self.threshold else 0 for p in proba]
        # 0 for payload  or  predict means unknown 
        if self.supported_apps != []:
            supported_predictions = [prediction if prediction in list(map(int, self.supported_apps)) else 0 for prediction in predicted_classes]
            return supported_predictions
        else:
            return predicted_classes

        
        



class RandomForest(Model):
    def __init__(self,sending_temp=True, sending_main=False ) -> None:
        self.sending_temp =  sending_temp
        self.sending_main = sending_main
    
    def preparation(self, df):
        batch_size = 1000
        num_batches = len(df) // batch_size + 1

        df_input_list = []
        for i in range(num_batches):
            batch = df.iloc[i * batch_size: (i + 1) * batch_size]
            df_input_attribute = batch['ipmeta'].apply(lambda x: create_data_ipmeta(x)).apply(pd.Series)
            df_input_batch = pd.concat([batch.drop(['ipmeta'], axis=1), df_input_attribute], axis=1)
            df_input_list.append(df_input_batch)

        df_input = pd.concat(df_input_list)
        df_input['ip'] = df_input['ip'].astype('category')
        df_input.reset_index()
        
        if 'label' in df_input.columns:
            single_row_classes = df_input.groupby('label').size()
            label_with_one_instance = single_row_classes[single_row_classes < 100].index.tolist()
            df_input.drop(df_input[df_input.label.isin(label_with_one_instance)].index, inplace=True)
            df_input.reset_index()
            df_input['label'] = df_input['label'].astype('category')
        
        return df_input

    def train(self):

        # Set display options
        pd.set_option('display.max_columns', None)
        pd.set_option('display.expand_frame_repr', False)
        logger.info(f"begin: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        self.dataset = self.load_dataset()
        self.dataset = list(filter(lambda x: check_ipmeta_completion(x[0])==True , self.dataset))
        df_meta = pd.DataFrame(self.dataset, columns=['ipmeta', 'label'])
        active_payload = [paylod.payload for paylod in Payload.objects.filter(generating=True)]
        max_ = df_meta.query(f"label in {active_payload}").groupby('label').size().max()
        sampled_data = df_meta.groupby('label',  group_keys=False).apply(lambda g : g.sample(n=min(max_, len(g)), random_state=42))
        filtered_df = sampled_data.groupby('label').filter(lambda x: len(x) >= 20) 

        df = self.preparation(filtered_df)
        
        numeric_features = df.select_dtypes(include=['int64', 'float64']).columns.values
        raw_x = df[numeric_features]
        Y = df['label']
        train_raw_x, test_raw_x, y_train, y_test = train_test_split(raw_x, Y, test_size=0.2, random_state=42)
        
        logger.info(f"getting hyperparameters: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        hyperparameters = self.get_hyperparameters(train_raw_x, y_train)
        logger.info(f"hyperparameters: \n{json.dumps(hyperparameters,indent=4)}")
        rf = MyRandomForestClassifier(
            n_estimators=hyperparameters['n_estimators'],
            max_features=hyperparameters['max_features'],
            max_depth=hyperparameters['max_depth'],
            criterion='gini',
            random_state=42,
            min_samples_leaf=hyperparameters['min_samples_leaf'],
            threshold=hyperparameters['threshold']
        )
        rf.fit(train_raw_x, y_train)
        logger.info(f"validating: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        y_pred = rf.predict(test_raw_x)
        report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
        supported_apps = list(map(lambda x: x[0], list(filter(lambda x: x[1]['precision'] >= 0.99 if type(x[1]) == dict and x[0] not in ['weighted avg','macro avg'] and x[1]['support'] > 20 else False,list(report.items())))))
        intersection = list(filter(lambda value: int(value) in active_payload, supported_apps))
        exclude_classes = [28392,27459]
        rf.supported_apps = [class_ for class_ in intersection if int(class_) not in exclude_classes]
        
        logger.info(f"supported_apps: {rf.supported_apps}")
        
        self.save_mlflow(rf, report, rf.supported_apps )
        self.save(rf)
        logger.info(f"end: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def predict(self, ipmetas, threshold, model_obj):
        df_input = pd.DataFrame(ipmetas, columns=['ipmeta'])
        df_input =  self.preparation(df_input)
        numeric_features = df_input.select_dtypes(include=['int64', 'float64']).columns.values
        raw_x = df_input[numeric_features]
        model_obj.threshold = threshold
        return list(filter(lambda x:x[1]!=0,list(zip(ipmetas,model_obj.predict(raw_x)))))

    def get_name(self):
        return {
            'full': 'RandomForestMulticlass',
            'abbreviated': 'RFM',
            'file': 'random_forest_multiclass'
        }

    def get_hyperparameters(self, train_x, y_train):
        
        def custom_scorer(estimator, X, y):
            y_pred = estimator.predict(X)
            report = classification_report(y, y_pred, output_dict=True, zero_division=0)
            return len(list(map(lambda x: x[0], list(filter(lambda x: x[1]['precision'] == 1 if type(x[1]) == dict and x[1]['support'] > 100 else False,list(report.items()))))))

        model = MyRandomForestClassifier()
        parameters = {
            'n_estimators': [200,100],
            'max_depth': [20],
            'max_features': ['sqrt'],
            'threshold': [0.9],
            'min_samples_leaf': [5,10]
        }
        grid_search = GridSearchCV(
            model,
            parameters,
            cv=5,
            scoring=custom_scorer,
        )
        grid_search.fit(train_x, y_train)
        return grid_search.best_params_
