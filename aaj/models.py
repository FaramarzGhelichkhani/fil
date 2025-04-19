import traceback
import joblib
from django.core.exceptions import ValidationError
from django.db import models
from django.utils import timezone
from fil.settings import MODELS_ADDRESS
from utils.mlflow_handler import MlflowHandeler
from khortum.models import Payload
from utils.ipmeta.classes import IpMeta


def validate_code(code):
    try:
        input_item = IpMeta(ip='0.0.0.0', asn='0', bsc=0, bcs=0, hit=0, percent=0, country='Nowhere', time='2020-12-20',
                            traffic=0)
        database_item = IpMeta(ip='0.0.0.0', asn='0', bsc=0, bcs=0, hit=0, percent=0, country='Nowhere',
                               time='2020-12-20', traffic=0)
        sim_model = joblib.load(MODELS_ADDRESS+'rf_similarity.joblib')                       
        local = {'database_item': database_item, 'input_item': input_item, 'similarity_model':sim_model}
        if any(x in code for x in ['os.', 'sys.', 'exit(', 'pause(', 'stop(', 'thread', 'process']):
            raise ValidationError("Nice try!")
        else:
            exec(code, globals(), local)
            return code
    except Exception as e:
        raise ValidationError(traceback.format_exc())


class Author(models.Model):
    name = models.CharField(max_length=256, null=False)

    def __str__(self):
        return str(self.name)


class Signature(models.Model):
    author = models.ForeignKey(Author, null=False, on_delete=models.DO_NOTHING)
    payload = models.ForeignKey(Payload, null=False, on_delete=models.DO_NOTHING, related_name='signatures')
    name = models.CharField(max_length=64, null=False)
    insert_time = models.DateTimeField(default=timezone.now, null=False)
    appdst = models.FloatField(null=False, default=1)
    sizedst = models.FloatField(null=False, default=1)
    portdst = models.FloatField(null=False, default=1)
    domaindst = models.FloatField(null=False, default=1)
    dnsdst = models.FloatField(null=False, default=1)
    script = models.TextField(validators=[validate_code])
    generating = models.BooleanField(default=True)
    needs_input = models.BooleanField(default=True)
    sending_temp = models.BooleanField(default=False)
    sending_main = models.BooleanField(default=False)

    def __str__(self):
        return str(self.author) + ' 4 ' + str(self.name) + ' @ ' + str(self.insert_time)


class Domain(models.Model):
    owner = models.ForeignKey('auth.User', related_name='domains', on_delete=models.CASCADE, default=None)
    domain_name = models.CharField(max_length=128, null=False)
    generating = models.BooleanField(default=True)
    sending_temp = models.BooleanField(default=False)
    sending_main = models.BooleanField(default=False)

    def __str__(self):
        return str(self.domain_name)


class IntelligentModel(models.Model):
    author = models.ForeignKey(Author, null=False, on_delete=models.DO_NOTHING)
    payload = models.ForeignKey(Payload, null=False, on_delete=models.DO_NOTHING, related_name='intelligent_models')
    name = models.CharField(max_length=128, null=False)
    file = models.CharField(max_length=256, null=True)
    acronym = models.CharField(max_length=64, null=False)
    insert_time = models.DateTimeField(default=timezone.now, null=False)
    update_time = models.DateTimeField(default=timezone.now, null=False)
    generating = models.BooleanField(default=True)
    sending_temp = models.BooleanField(default=False)
    sending_main = models.BooleanField(default=False)
    config = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"{self.name}_{self.payload.name}"

    class Meta:
        verbose_name = "Intelligent Model"
        verbose_name_plural = "Intelligent Models"
        ordering = ["-update_time"]
        db_table = "intelligent_model"

    def _load_mlflow_handler(self):
        return MlflowHandeler(model_name=self.__str__())

    def load_ml_model_obj(self, version=None):
        mlflow = self._load_mlflow_handler()
        return mlflow.load_model(version=version)

