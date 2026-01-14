from pydantic import BaseModel, ConfigDict, field_validator

from .match import coerce_int


class SliceNode(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: int
    label: str
    name: str = ""
    code: str = ""
    typeFullName: str = ""
    parentMethod: str = ""
    parentFile: str = ""
    lineNumber: int | None = None
    columnNumber: int | None = None

    @field_validator("lineNumber", "columnNumber", mode="before")
    @classmethod
    def _validate_ints(cls, v: int | None) -> int | None:
        return coerce_int(v)


class SliceEdge(BaseModel):
    src: int
    dst: int
    label: str


class Slice(BaseModel):
    nodes: list[SliceNode]
    edges: list[SliceEdge]
    sinkIds: list[int] = []
    originIds: list[int] = []
    paramUsageIds: list[int] = []

    @classmethod
    def from_json(cls, data: dict) -> "Slice":
        extra_nodes = data.pop("extraNodes", None)
        if extra_nodes:
            data["nodes"] = list(data.get("nodes", [])) + list(extra_nodes)
        return cls.model_validate(data)
