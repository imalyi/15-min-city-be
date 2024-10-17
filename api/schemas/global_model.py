from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel


# TODO change name to Base
class GlobalModelWithJSONAlias(BaseModel):
    """
    Used for every model
    """

    model_config = ConfigDict(
        alias_generator=to_camel, populate_by_name=True, extra="ignore"
    )
