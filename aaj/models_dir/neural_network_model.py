from aaj.utils.preparing import create_data
import torch    
import torch.nn as nn
import logging
import pandas as pd 
from aaj.utils.model import Model
from sklearn.preprocessing import StandardScaler
from sklearn.inspection import permutation_importance
from sklearn.metrics import classification_report

logger = logging.getLogger("ip_classification.main")


class Net(nn.Module):
    
    def __init__(self,input_dim, layer1=3, layer2=4,**kwargs):
        super(Net,self).__init__()
        self.fc1 = nn.Linear(input_dim,layer1)
        self.fc2 = nn.Linear(layer1,layer2)
        self.fc3 = nn.Linear(layer2,1)  
    
    def forward(self,x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        x = torch.sigmoid(self.fc3(x))
        return x

class NeuralNetworkModel_Binary(Model): 

    def __init__(self):
        super(NeuralNetworkModel_Binary, self).__init__()

    def _get_feteures(self):
        
        asn = ['asn']
        
        general = ['total_traffic', 'total_hit',
       'bytes_ratio', 'hit_traffic_ratio', 'value', 'sni']
        
        dns= [ 'count_dns', 'dns_percent_mean',
            'dns_percent_var', 'dns_length_mean', 'dns_length_var',
            'dns_tld_percent_com', 'dns_tld_percent_org', 'dns_tld_percent_net',
            'dns_tld_percent_ir', 'dns_tld_percent_other',
            'dns_number_of_consonants', 'dns_number_of_vowels', 'dns_mean_subs',
            'dns_variance_sub']
        
        port = ['count_port', 'port_mean_percent', 'port_variance_percent',
            'port443_percent', 'port53_percent', 'port80_percent', 'port0_percent',
            'none_default_port_number', 'none_default_port_percent']

        domain = ['count_domain',
            'null_domain_percent', 'domain_percent_mean', 'domain_percent_var',
            'domain_length_mean', 'domain_length_var', 'domain_tld_percent_com',
            'domain_tld_percent_org', 'domain_tld_percent_net',
            'domain_tld_percent_ir', 'domain_tld_percent_other',
            'domain_number_of_consonants', 'domain_number_of_vowels',
            'domain_mean_subs', 'domain_variance_sub']
        
        detection = ['tcp', 'udp', 'ssl', 'dns',
            'https', 'http', 'freeze', 'Iran', 'detect_percent_mean',
            'detect_percent_var']

        features = general + dns + port + domain + detection
        
        return features

    def get_params(self):
        """"To return hyperparameters."""
        self.params["payload_asns"] = self.payload_asns
        return self.params


    def set_asns(self):
        asn_counts = self.df[self.df.label==self.payload]["asn"].value_counts()
        total_count = asn_counts.sum()
        threshold = 0.9 
        cumulative_sum = 0 
        selected_keys = []
        for key, repetition in  zip(asn_counts.index.to_list(),asn_counts.to_list()):
            if cumulative_sum > threshold or repetition < 15:
                break
            cumulative_sum += repetition/total_count
            selected_keys.append(key)
        
        drop_index = self.df[(~self.df["asn"].isin(selected_keys)) &(self.df.label==self.payload)].index
        self.df.drop(drop_index, inplace=True)    
        self.payload_asns = [int(asn) for asn in selected_keys]
        return self.df

    def preprocess(self, feature_names=False):

        self.df.dropna(inplace=True)
        target_index = self.df.loc[self.df.label == self.payload].index
        
        if len(target_index) < 100 :
            raise ValueError("number is instance is not enough.")
        

        sample_df = self.df.groupby("label", as_index=False).apply(lambda s: s.sample(min(len(s), len(target_index)), random_state=42)).reset_index(drop=True)
        sample_df["binary_tag"] = sample_df["label"].apply(lambda x: 1 if x == self.payload else 0)
        false_index = sample_df.query("binary_tag == 0").index
        n_sample = int(1.5 * len(target_index)) 
        sample_data = pd.concat([sample_df.query("binary_tag == 1"), sample_df.loc[false_index]], axis=0)
        sample_data = sample_data.groupby(["binary_tag","label"], as_index=False).apply(lambda s: s.sample(min(len(s), n_sample), random_state=42)).reset_index(drop=True)
        self.df = sample_data
        sample_data=  self.set_asns()
        scaler = StandardScaler()
        if feature_names == False:
            feature_names = self._get_feteures()
        
        self.feature_names = feature_names
        x = sample_data[feature_names]
        X_scaled = scaler.fit_transform(x)
        labels = sample_data[["binary_tag"]].values
        self.scaler = scaler

        return X_scaled, labels

    def train(self, dataset=False, feature_names=False, **kwargs):
        import torch.optim as optim
        from   torch.utils.data import DataLoader, TensorDataset, random_split
        
        X_scaled, y_= self.preprocess(feature_names)
        X = torch.tensor(X_scaled, dtype=torch.float32)
        y = torch.tensor(y_, dtype=torch.float32)
        # dataset = TensorDataset(X, y.unsqueeze(1))
        dataset = TensorDataset(X, y)
        train_size = int(0.8 * len(dataset))
        val_size = len(dataset) - train_size
        train_dataset, val_dataset = random_split(dataset, [train_size, val_size])
        model = Net(input_dim=X.shape[1],**kwargs)
        logger.info(f"model structure: {model}")
        # training
        self.params = kwargs
        LEARNING_RATE = kwargs.get("LEARNING_RATE",0.1)
        BATCH_SIZE= kwargs.get("BATCH_SIZE",32)
        EPOCHS= kwargs.get("EPOCHS",400)
        PROBABILITY_THERESHOLD =  kwargs.get("PROBABILITY_THERESHOLD",0.5)
        self.threshold = PROBABILITY_THERESHOLD

        optimizer = optim.SGD(model.parameters(), lr=LEARNING_RATE)
        loss_fn = nn.BCELoss()
        train_loader = DataLoader(train_dataset, batch_size=BATCH_SIZE, shuffle=True)
        val_loader = DataLoader(val_dataset, batch_size=BATCH_SIZE, shuffle=False)

        for epoch in range(EPOCHS):
            model.train()
            for batch_X, batch_y in train_loader:
                optimizer.zero_grad()
                outputs = model(batch_X)
                
                loss = loss_fn(outputs, batch_y)
                loss.backward()
                optimizer.step()
            
            if (epoch + 1) % 100 == 0:
                logger.info(f'Epoch [{epoch + 1}/{EPOCHS}], Loss: {loss.item():.4f}')
        
        model.feature_importances_ = []
        model.feature_names = self.feature_names
        # Validation
        model.eval()
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                outputs = model(batch_X)
                preds = (outputs > PROBABILITY_THERESHOLD).float() 
                all_preds.append(preds)
                all_labels.append(batch_y)

        all_preds = torch.cat(all_preds).cpu().numpy()
        all_labels = torch.cat(all_labels).cpu().numpy()

        self.report = classification_report(all_labels, all_preds, output_dict=True, zero_division=0, target_names=[0, 1])
        logger.info(f'Precision: { self.report[1]["precision"]:.4f}, Recall: {self.report[1]["recall"]:.4f}')
        logger.info(f"start to cal feature importanc...")
        self.model_obj = model
        wrapper_model = Wrapper_Model(model=model, threshold=self.threshold)
        importance = permutation_importance(
                    estimator=wrapper_model,
                    X=batch_X,
                    y=batch_y,
                    scoring='accuracy',
                    n_repeats=10,
                    random_state=42,
                    n_jobs=None,
                        )
        self.model_obj.feature_importances_ = sorted(zip(self.feature_names, importance.importances_mean), key=lambda x: x[1], reverse=True)
        self.feature_importances_ = self.model_obj.feature_importances_
        self.feature_importances = False
        
    def predict(self, context=None, model_input={"ipmetas":[]}, params=None):        
        if type(context) == dict:
            model_input = context
        ipmetas= model_input["ipmetas"] # list of ipmetas
        threshold = model_input.get('threshold',self.threshold)  

        df = create_data(ipmetas=ipmetas, return_X_y=False)
        x = df[self.feature_names]
        self.model_obj.eval()  
        with torch.no_grad():  
            instances_scaled = self.scaler.transform(x)
            instances_tensor = torch.tensor(instances_scaled, dtype=torch.float32)
            outputs = self.model_obj(instances_tensor)
            predicted_classes = (outputs >= threshold).numpy().astype(int).flatten()
        for index , ip in enumerate(ipmetas):
            if ip.asn not in self.payload_asns:
                predicted_classes[index]=0
        return predicted_classes

class Wrapper_Model():
   
    def __init__(self, model, threshold=0.5) :
        self.model_obj = model
        self.threshold = threshold

    def fit(self, X,y):
        # This method is just a placeholder and will not be used
        pass

    def predict(self,X):
        self.model_obj.eval()
        with torch.no_grad():
            X_tensor = torch.tensor(X, dtype=torch.float32)
            outputs = self.model_obj(X_tensor)
            predicted_classes = (outputs >= self.threshold).numpy().astype(int).flatten()
        return predicted_classes
