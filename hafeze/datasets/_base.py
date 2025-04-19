import os
import glob
import pickle
import pandas as pd 
import datasets
from aaj.utils.preparing import create_data
from fil.settings import  DATASET_RAW_FILES, DATASET_ADDRESS
from khortum.management.commands.label import fetch_input_ipmeta_from_fil



def _read_file(data_file_pattern):
    file_pattern = os.path.join(DATASET_RAW_FILES, data_file_pattern)
    matching_files = glob.glob(file_pattern)
    result = []
    for file in matching_files:
        if file.endswith(".csv"):
            with open(file, 'rb') as file:
                while True:
                    try:
                        data = pickle.load(file)
                        result.append(data)
                    except EOFError:
                        # reached the end of the file
                        break
    ipmetas = []
    for row in result:
        ipmeta = row[0]
        ipmeta.label= row[1]
        ipmetas.append(ipmeta)
    
    return ipmetas

def load_data(data_file_pattern, return_X_y=False, ipmetas=None):
    if ipmetas is None:
        ipmetas = _read_file(data_file_pattern=data_file_pattern)
    return create_data(ipmetas=ipmetas, return_X_y=return_X_y)
     
def load_Iran(return_X_y=False):
    data_file_name = "Iran-*.csv"
    return load_data(data_file_pattern=data_file_name, return_X_y=return_X_y )
       
def load_jamal(*, return_X_y=False):
    data_file_name = "w-*.csv"
    return load_data(data_file_pattern=data_file_name, return_X_y=return_X_y )

def load_Freeze(return_X_y=False):
    data_file_name = "Freeze-*.csv"
    return load_data(data_file_pattern=data_file_name, return_X_y=return_X_y )

def load_Fil_input(return_X_y=False, db_host=None, db_name=None):
    ipmetas = fetch_input_ipmeta_from_fil(offset_days='30 day',db_host=db_host, db_name=db_name,save=False)
    return load_data(data_file_pattern=None, return_X_y=return_X_y, ipmetas=ipmetas )

def load_all_data(return_X_y=False,db_host=None, db_name=None):
    "return dataframe or array for all data."
    Iran_df = load_Iran()
    jamal_df= load_jamal()
    freeze_df= load_Freeze() 
    fil_input_df= load_Fil_input(db_host=db_host, db_name=db_name)
    combined_df = pd.concat([Iran_df, jamal_df, freeze_df, fil_input_df], axis=0)
    
    if return_X_y:
        numerical_feature_name = combined_df.columns[5:-2] # based on feature in preparing module.
        X = combined_df[numerical_feature_name].values
        y = combined_df['label'].values
        return X, y
    
    return combined_df

def load_dataset():
        return [pickle.loads(data['labeled_data']) for data in datasets.load_from_disk(dataset_path=DATASET_ADDRESS)]
