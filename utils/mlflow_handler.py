import mlflow
import joblib
import logging
from fil.settings import MLFLOW_HOST, MODELS_ADDRESS
from utils.utils import get_last_day
from typing import Dict, List

logger = logging.getLogger("ip_classification.main")
mlflow.set_tracking_uri(f'https://{MLFLOW_HOST}/mlflow')


class MlflowHandeler:
    def __init__(self, model_name, experiment_name = "Models Fil"):
        self.model_name = model_name
        self.experiment_name = experiment_name
        self.stage = "Production"

    def save_mlflow(self, model, dataset=None, code_file=None, hyper_parameteres: Dict[str,str] =None,metrics: Dict[str, float] =None,  feature_importance: Dict[str,str] =None, signature=None):
        mlflow.set_experiment(self.experiment_name)
        
        if not isinstance(model, mlflow.pyfunc.PythonModel):
            logger.error("it is not pyfunc instance.")

            
        with mlflow.start_run(run_name=f'{self.model_name} {get_last_day(0)}'):
            # model obj 
            mlflow.pyfunc.log_model(artifact_path="model", python_model=model, code_path=code_file, registered_model_name=self.model_name, signature=signature)
            
            # dataset 
            if dataset is not None: 
                # dataset = mlflow.data.from_pandas(df_dataset, targets="tag", predictions="ModelOutput")
                mlflow.log_input(dataset, context="training and test")
                # mlflow.log_artifact(dataset, "Datasets")
            
            # hyper parametere
            if hyper_parameteres is not None:
                mlflow.log_params(hyper_parameteres)
            
            # feature importance
            if feature_importance is not None:
                # mlflow.log_param("Feature Importances", str(feature_importance))    
                mlflow.log_artifact(feature_importance, artifact_path="Feature Importances")

            if metrics is not None:
                mlflow.log_metrics(metrics=metrics)    
            
    def load_model(self, version=None):
        try:
            return self._load_model_mlflow(version=version)
        except Exception as e:
            logger.warning(f"{e}")
            logger.warning("it is using model from fil.")
            return joblib.load(f"{MODELS_ADDRESS}{self.model_name}.joblib")
    
    def load_dataset_from_mlflow(self,version=None):
        return self._load_mlflow(version,dataset=True)
    
    def _load_mlflow(self, version=None, model=False, dataset=False):
        if version is None:
            filter_string=f'tags.stage = "{self.stage}" and tags.mlflow.runName like "{self.model_name}%"'
        else:
            filter_string=f'tags.mlflow.runName like "{self.model_name}%" and tags.mlflow.source.name = "models" and tags.mlflow.source.version = "{version}"'
        
        runs = mlflow.search_runs(experiment_names=[self.experiment_name], filter_string=filter_string, order_by=["start_time desc"], max_results=1)
        if not runs.empty:
            run_id = runs.iloc[0].run_id

            if model:
                return  mlflow.pyfunc.load_model(f"runs:/{run_id}/model")
            
            with mlflow.start_run(run_id=run_id):
                if dataset:
                    return mlflow.get_artifact_uri(artifact_path='Datasets')
        else:
            logger.error(f"No runs found for experiment {self.experiment_name}, model name with {self.model_name}.")
            return False 

    def _load_model_mlflow(self,version=None):
        if version is None:
            model = mlflow.pyfunc.load_model(model_uri=f"models:/{self.model_name}/{self.stage}")
        else: 
            model = mlflow.pyfunc.load_model(model_uri=f"models:/{self.model_name}/{version}")
        return model

    def get_production_version(self):
        client = mlflow.MlflowClient()
        version = 0
        for mv in client.search_model_versions(f"name='{self.model_name}'"):
            if mv.current_stage == self.stage:
                version = max(version, int(mv.version))
        return version
