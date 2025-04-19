import logging
import os
import pandas as pd
import importlib
from django.core.management.base import BaseCommand
from utils.mlflow_handler import MlflowHandeler
from aaj.models import IntelligentModel
from hafeze.datasets import load_dataset, load_all_data
from fil.settings import PRODUCTION_SERVER

logger = logging.getLogger("ip_classification")

class Command(BaseCommand):

    def handle(self, *args, **options):

        models = IntelligentModel.objects.filter(generating=True)
        if len(models) == 0:
            logger.error("no model to train.")
            raise ValueError("no model to train.")
        
        logger.info(f"loading data...")
        dataset = load_dataset()
        df= load_all_data(return_X_y=False,db_host=PRODUCTION_SERVER,db_name='fildb_production')
        logger.info(f"loading data finished.")

        for model in models:
            try:
                module_path= model.file
                config = eval(model.config)
                module = importlib.import_module(module_path)
                class_obj = getattr(module, model.name)
                logger.info(f"start to train for {model.__str__()}")
                obj = class_obj()
                obj.name = model.name 
                obj.payload_name = model.payload.name
                obj.payload = model.payload.payload
                obj.df= df
                obj.train(dataset=dataset, **config)
                logger.info("train finished.", {"command": "train"})
                obj.save_model_fil()
                logger.info("save model as joblib finished.", {"command": "train"})
                dataset, metric, feature_importance_file = obj.generate_mlflow_options(obj.df)
                
                mlflow_obj = MlflowHandeler(model_name=model.__str__())
                mlflow_obj.save_mlflow(model=obj, dataset=dataset, code_file=[module_path.replace('.','/')+'.py'], hyper_parameteres=obj.get_params(), metrics=metric, feature_importance=feature_importance_file, signature=None)
                logger.info(f"save {model.__str__()} on mlflow finished.", {"command": "train"})
                model.save() 
                os.remove(feature_importance_file)
            except Exception as e:
                logger.error(e)
                continue
        logger.info("train finished.", {"command": "train"})
