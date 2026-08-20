from __future__ import annotations

import base64
import logging
import time
from collections.abc import Callable
from enum import IntEnum
from typing import TYPE_CHECKING, Any

import ida_dirtree
import ida_frame
import ida_funcs
import ida_idp
import ida_moves
import ida_range
import ida_segment
import ida_typeinf
import ida_ua

if TYPE_CHECKING:
    import ida_nalt

logger = logging.getLogger(__name__)


class _Record(dict[str, Any]):
    """Primitive snapshot of an IDA SDK object."""

    def __init__(self, **fields: Any) -> None:
        super().__init__(fields)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _event(**fields: Any) -> dict[str, Any]:
    fields["timestamp"] = time.time_ns()
    if "_from" in fields:
        source_name = (
            "from_path" if fields["event_name"] == "dirtree_move" else "from_ea"
        )
        fields[source_name] = fields.pop("_from")
    for name, value in fields.items():
        if isinstance(value, bytes):
            fields[name] = base64.b64encode(value).decode("ascii")
    return fields


class FuncModel(_Record):
    """Snapshot of an ida_funcs.func_t structure."""

    start_ea: int
    end_ea: int
    flags: int
    frame: int
    frsize: int
    frregs: int
    argsize: int
    fpd: int
    color: int
    pntqty: int
    regvarqty: int
    regargqty: int
    tailqty: int
    owner: int
    refqty: int
    name: str | None = None

    @classmethod
    def from_func_t(cls, func: ida_funcs.func_t) -> FuncModel:
        """Create FuncModel from ida_funcs.func_t instance."""
        import ida_funcs

        name = ida_funcs.get_func_name(func.start_ea)
        return cls(
            start_ea=func.start_ea,
            end_ea=func.end_ea,
            flags=func.flags,
            frame=func.frame,
            frsize=func.frsize,
            frregs=func.frregs,
            argsize=func.argsize,
            fpd=func.fpd,
            color=func.color,
            pntqty=func.pntqty,
            regvarqty=func.regvarqty,
            regargqty=func.regargqty,
            tailqty=func.tailqty,
            owner=func.owner,
            refqty=func.refqty,
            name=name if name else None,
        )


class OpModel(_Record):
    """Snapshot of an ida_ua.op_t structure."""

    n: int
    type: int
    offb: int
    offo: int
    flags: int
    dtype: int
    reg: int
    phrase: int
    value: int
    addr: int
    specval: int
    specflag1: int
    specflag2: int
    specflag3: int
    specflag4: int

    @classmethod
    def from_op_t(cls, op: ida_ua.op_t) -> OpModel:
        """Create OpModel from ida_ua.op_t instance."""
        return cls(
            n=op.n,
            type=op.type,
            offb=op.offb,
            offo=op.offo,
            flags=op.flags,
            dtype=op.dtype,
            reg=op.reg,
            phrase=op.phrase,
            value=op.value,
            addr=op.addr,
            specval=op.specval,
            specflag1=op.specflag1,
            specflag2=op.specflag2,
            specflag3=op.specflag3,
            specflag4=op.specflag4,
        )


class InsnModel(_Record):
    """Snapshot of an ida_ua.insn_t structure."""

    cs: int
    ip: int
    ea: int
    itype: int
    size: int
    auxpref: int
    segpref: int
    insnpref: int
    flags: int
    ops: list[OpModel]

    @classmethod
    def from_insn_t(cls, insn: ida_ua.insn_t) -> InsnModel:
        """Create InsnModel from ida_ua.insn_t instance."""
        return cls(
            cs=insn.cs,
            ip=insn.ip,
            ea=insn.ea,
            itype=insn.itype,
            size=insn.size,
            auxpref=insn.auxpref,
            segpref=insn.segpref,
            insnpref=insn.insnpref,
            flags=insn.flags,
            ops=[OpModel.from_op_t(insn.ops[i]) for i in range(8)],
        )


class SegmentModel(_Record):
    """Snapshot of an ida_segment.segment_t structure."""

    start_ea: int
    end_ea: int
    name: int
    sclass: int
    orgbase: int
    align: int
    comb: int
    perm: int
    bitness: int
    flags: int
    sel: int
    defsr: list[int]
    type: int
    color: int
    segment_name: str | None = None
    segment_class: str | None = None

    @classmethod
    def from_segment_t(cls, segment: ida_segment.segment_t) -> SegmentModel:
        """Create SegmentModel from ida_segment.segment_t instance."""
        import ida_segment

        defsr_list = [segment.defsr[i] for i in range(16)]
        return cls(
            start_ea=segment.start_ea,
            end_ea=segment.end_ea,
            name=segment.name,
            sclass=segment.sclass,
            orgbase=segment.orgbase,
            align=segment.align,
            comb=segment.comb,
            perm=segment.perm,
            bitness=segment.bitness,
            flags=segment.flags,
            sel=segment.sel,
            defsr=defsr_list,
            type=segment.type,
            color=segment.color,
            segment_name=ida_segment.get_segm_name(segment) if segment else None,
            segment_class=ida_segment.get_segm_class(segment) if segment else None,
        )


class RangeModel(_Record):
    """Snapshot of an ida_range.range_t structure."""

    start_ea: int
    end_ea: int

    @classmethod
    def from_range_t(cls, range_obj: ida_range.range_t) -> RangeModel:
        """Create RangeModel from ida_range.range_t instance.

        Args:
            range_obj: The range_t instance to convert.

        Returns:
            RangeModel instance with populated attributes.
        """
        return cls(start_ea=range_obj.start_ea, end_ea=range_obj.end_ea)


class CatchModel(_Record):
    """Snapshot of a C++ catch_t structure."""

    ranges: list[RangeModel]
    disp: int
    fpreg: int
    obj: int
    type_id: int

    @classmethod
    def from_catch_t(cls, catch_obj) -> CatchModel:
        return cls(
            ranges=[
                RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in catch_obj
            ],
            disp=catch_obj.disp,
            fpreg=catch_obj.fpreg,
            obj=catch_obj.obj,
            type_id=catch_obj.type_id,
        )


class SehModel(_Record):
    """Snapshot of an SEH exception handler."""

    ranges: list[RangeModel]
    disp: int
    fpreg: int
    filter_ranges: list[RangeModel]
    seh_code: int

    @classmethod
    def from_seh_t(cls, seh_obj) -> SehModel:
        return cls(
            ranges=[RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in seh_obj],
            disp=seh_obj.disp,
            fpreg=seh_obj.fpreg,
            filter_ranges=[
                RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in seh_obj.filter
            ],
            seh_code=seh_obj.seh_code,
        )


class TryblkModel(_Record):
    """Snapshot of a tryblk_t structure."""

    kind: str
    level: int
    ranges: list[RangeModel]
    catches: list[CatchModel] | None = None
    seh: SehModel | None = None

    @classmethod
    def from_tryblk_t(cls, tb) -> TryblkModel:
        ranges = [RangeModel(start_ea=r.start_ea, end_ea=r.end_ea) for r in tb]
        kind_map = {0: "none", 1: "seh", 2: "cpp"}
        kind = kind_map.get(tb.get_kind(), "unknown")
        catches = None
        seh = None
        if tb.is_cpp():
            catches = [CatchModel.from_catch_t(c) for c in tb.cpp()]
        elif tb.is_seh():
            seh = SehModel.from_seh_t(tb.seh())
        return cls(kind=kind, level=tb.level, ranges=ranges, catches=catches, seh=seh)


class UdmModel(_Record):
    """Snapshot of an ida_typeinf.udm_t structure."""

    offset: int
    size: int
    name: str
    cmt: str
    type_name: str
    repr: str
    effalign: int
    tafld_bits: int
    fda: int

    @classmethod
    def from_udm_t(cls, udm: ida_typeinf.udm_t) -> UdmModel:
        return cls(
            offset=udm.offset,
            size=udm.size,
            name=udm.name,
            cmt=udm.cmt,
            type_name=udm.type.get_type_name() or "(unnamed)",
            repr=str(udm.repr),
            effalign=udm.effalign,
            tafld_bits=udm.tafld_bits,
            fda=udm.fda,
        )


class EdmModel(_Record):
    """Snapshot of an ida_typeinf.edm_t structure."""

    name: str
    comment: str
    value: int

    @classmethod
    def from_edm_t(cls, edm: ida_typeinf.edm_t) -> EdmModel:
        return cls(name=edm.name, comment=edm.cmt, value=edm.value)


class RefInfoModel(_Record):
    """Model for offset/reference operand info (refinfo_t)."""

    target: int
    base: int
    tdelta: int
    flags: int
    ref_type: int
    target_name: str | None = None

    @classmethod
    def from_refinfo_t(cls, ri: ida_nalt.refinfo_t) -> RefInfoModel:
        import idc

        target_name = None
        if ri.target != idc.BADADDR:
            target_name = idc.get_name(ri.target) or None
        return cls(
            target=ri.target,
            base=ri.base,
            tdelta=ri.tdelta,
            flags=ri.flags,
            ref_type=ri.type(),
            target_name=target_name,
        )


class EnumConstModel(_Record):
    """Model for enum constant operand info (enum_const_t)."""

    tid: int
    serial: int
    enum_name: str | None = None

    @classmethod
    def from_enum_const_t(cls, ec: ida_nalt.enum_const_t) -> EnumConstModel:
        import ida_typeinf

        enum_name = ida_typeinf.get_tid_name(ec.tid) or None
        return cls(tid=ec.tid, serial=ec.serial, enum_name=enum_name)


class StrPathModel(_Record):
    """Model for struct offset path operand info (strpath_t)."""

    path_len: int
    path_ids: list[int]
    delta: int
    path_names: list[str]

    @classmethod
    def from_strpath_t(cls, path: ida_nalt.strpath_t) -> StrPathModel:
        import ida_typeinf

        path_ids = [path.ids[i] for i in range(path.len)]
        path_names = []
        for tid in path_ids:
            name = ida_typeinf.get_tid_name(tid)
            path_names.append(name if name else "(unnamed)")
        return cls(
            path_len=path.len,
            path_ids=path_ids,
            delta=path.delta,
            path_names=path_names,
        )


class OpInfoModel(_Record):
    """Model for operand type info (opinfo_t union).

    The opinfo_t is a union - only one field is valid depending on the operand flags.
    """

    kind: str
    refinfo: RefInfoModel | None = None
    enum_const: EnumConstModel | None = None
    strpath: StrPathModel | None = None
    struct_tid: int | None = None
    struct_name: str | None = None
    strtype: int | None = None

    @classmethod
    def from_opinfo_t(cls, opinfo: ida_nalt.opinfo_t) -> OpInfoModel | None:
        import ida_typeinf
        import idc

        if opinfo is None:
            return None
        ri = opinfo.ri
        if ri.type() != 0:
            return cls(kind="offset", refinfo=RefInfoModel.from_refinfo_t(ri))
        ec = opinfo.ec
        if ec.tid != 0 and ec.tid != idc.BADADDR:
            return cls(kind="enum", enum_const=EnumConstModel.from_enum_const_t(ec))
        path = opinfo.path
        if path.len > 0:
            return cls(kind="stroff", strpath=StrPathModel.from_strpath_t(path))
        tid = opinfo.tid
        if tid != 0 and tid != idc.BADADDR:
            struct_name = ida_typeinf.get_tid_name(tid) or None
            return cls(kind="struct", struct_tid=tid, struct_name=struct_name)
        strtype = opinfo.strtype
        if strtype != 0:
            return cls(kind="string", strtype=strtype)
        return None

    @classmethod
    def from_database(cls, ea: int, n: int) -> OpInfoModel | None:
        """Create OpInfoModel by querying the database for current operand info at ea, n."""
        import ida_bytes
        import ida_nalt
        import ida_typeinf

        flags = ida_bytes.get_flags(ea)
        if ida_bytes.is_off(flags, n):
            ri = ida_nalt.refinfo_t()
            if ida_nalt.get_refinfo(ri, ea, n):
                return cls(kind="offset", refinfo=RefInfoModel.from_refinfo_t(ri))
        if ida_bytes.is_enum(flags, n):
            opinfo = ida_nalt.opinfo_t()
            if ida_bytes.get_opinfo(opinfo, ea, n, flags):
                return cls(
                    kind="enum", enum_const=EnumConstModel.from_enum_const_t(opinfo.ec)
                )
        if ida_bytes.is_stroff(flags, n):
            opinfo = ida_nalt.opinfo_t()
            if ida_bytes.get_opinfo(opinfo, ea, n, flags):
                return cls(
                    kind="stroff", strpath=StrPathModel.from_strpath_t(opinfo.path)
                )
        if ida_bytes.is_struct(flags):
            opinfo = ida_nalt.opinfo_t()
            if ida_bytes.get_opinfo(opinfo, ea, n, flags):
                struct_name = ida_typeinf.get_tid_name(opinfo.tid) or None
                return cls(
                    kind="struct", struct_tid=opinfo.tid, struct_name=struct_name
                )
        return None


class SegmMoveInfoModel(_Record):
    """Snapshot of an ida_moves.segm_move_info_t structure."""

    from_ea: int
    to_ea: int
    size: int

    @classmethod
    def from_segm_move_info_t(cls, info) -> SegmMoveInfoModel:
        return cls(from_ea=info._from, to_ea=info.to, size=info.size)


class LocalTypeChange(IntEnum):
    ADDED = 1
    DELETED = 2
    EDITED = 3
    ALIASED = 4
    COMPILER = 5
    TIL_LOADED = 6
    TIL_UNLOADED = 7
    TIL_COMPACTED = 8


def deserialize_type_to_str(type_bytes: bytes, fnames_bytes: bytes) -> str | None:
    """Deserialize IDA type bytes to a human-readable string.

    Args:
        type_bytes: The serialized type bytes from IDA hooks.
        fnames_bytes: The serialized field names bytes.

    Returns:
        Human-readable type string, or None if deserialization fails.
    """
    if not type_bytes:
        return None
    try:
        tif = ida_typeinf.tinfo_t()
        fnames = fnames_bytes if fnames_bytes else None
        if tif.deserialize(None, type_bytes, fnames):
            return tif.dstr()
        return None
    except Exception:  # noqa: BLE001 - IDA type deserialization is best-effort
        return None


class IDBEventHook(ida_idp.IDB_Hooks):
    def __init__(
        self,
        sink: Callable[[dict[str, Any], str | None, str | None, str | None], None],
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self._sink = sink
        self.operation_id: str | None = None
        self.operation_label: str | None = None
        self.origin_id: str | None = None
        self._pending_delete_func_names: dict[int, str] = {}

    def _emit(self, event: dict[str, Any]) -> None:
        self._sink(
            event,
            self.operation_id,
            self.operation_label,
            self.origin_id,
        )

    ### loading events

    def determined_main(self, main: int) -> None:
        """The main() function has been determined."""
        logger.debug("determined_main(main=%d)", main)
        ev = _event(event_name="determined_main", main=main)
        self._emit(ev)

    def idasgn_matched_ea(self, ea: int, name: str, lib_name: str) -> None:
        """A FLIRT match has been found."""
        logger.debug(
            "idasgn_matched_ea(ea=%d, name=%s, lib_name=%s)", ea, name, lib_name
        )
        ev = _event(
            event_name="idasgn_matched_ea",
            ea=ea,
            name=name,
            lib_name=lib_name,
        )
        self._emit(ev)

    ### segment operations

    def adding_segm(self, s: ida_segment.segment_t) -> None:
        """A segment is being created."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("adding_segm(s=%s)", s_model)
        ev = _event(event_name="adding_segm", s=s_model)
        self._emit(ev)

    def segm_added(self, s: ida_segment.segment_t) -> None:
        """A new segment has been created.

        See also adding_segm.

        Args:
            s: Segment object.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_added(s=%s)", s_model)
        ev = _event(event_name="segm_added", s=s_model)
        self._emit(ev)

    def deleting_segm(self, start_ea: int) -> None:
        """A segment is to be deleted."""
        logger.debug("deleting_segm(start_ea=%d)", start_ea)
        ev = _event(event_name="deleting_segm", start_ea=start_ea)
        self._emit(ev)

    def segm_deleted(self, start_ea: int, end_ea: int, flags: int) -> None:
        """A segment has been deleted."""
        logger.debug(
            "segm_deleted(start_ea=%d, end_ea=%d, flags=%d)", start_ea, end_ea, flags
        )
        ev = _event(
            event_name="segm_deleted",
            start_ea=start_ea,
            end_ea=end_ea,
            flags=flags,
        )
        self._emit(ev)

    def changing_segm_start(
        self, s: ida_segment.segment_t, new_start: int, segmod_flags: int
    ) -> None:
        """Segment start address is to be changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug(
            "changing_segm_start(s=%s, new_start=%d, segmod_flags=%d)",
            s_model,
            new_start,
            segmod_flags,
        )
        ev = _event(
            event_name="changing_segm_start",
            s=s_model,
            new_start=new_start,
            segmod_flags=segmod_flags,
        )
        self._emit(ev)

    def segm_start_changed(self, s: ida_segment.segment_t, oldstart: int) -> None:
        """Segment start address has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_start_changed(s=%s, oldstart=%d)", s_model, oldstart)
        ev = _event(
            event_name="segm_start_changed",
            s=s_model,
            oldstart=oldstart,
        )
        self._emit(ev)

    def changing_segm_end(
        self, s: ida_segment.segment_t, new_end: int, segmod_flags: int
    ) -> None:
        """Segment end address is to be changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug(
            "changing_segm_end(s=%s, new_end=%d, segmod_flags=%d)",
            s_model,
            new_end,
            segmod_flags,
        )
        ev = _event(
            event_name="changing_segm_end",
            s=s_model,
            new_end=new_end,
            segmod_flags=segmod_flags,
        )
        self._emit(ev)

    def segm_end_changed(self, s: ida_segment.segment_t, oldend: int) -> None:
        """Segment end address has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_end_changed(s=%s, oldend=%d)", s_model, oldend)
        ev = _event(
            event_name="segm_end_changed",
            s=s_model,
            oldend=oldend,
        )
        self._emit(ev)

    def changing_segm_name(self, s: ida_segment.segment_t, oldname: str) -> None:
        """Segment name is being changed.

        s.name == oldname

        See also segm_name_changed, which has the new name.
        There's not an event with both old and new names.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("changing_segm_name(s=%s, oldname=%s)", s_model, oldname)
        ev = _event(
            event_name="changing_segm_name",
            s=s_model,
            oldname=oldname,
        )
        self._emit(ev)

    def segm_name_changed(self, s: ida_segment.segment_t, name: str) -> None:
        """Segment name has been changed.

        s.name == name (new name)

        See also changing_segm_name, which has the old name.
        There's not an event with both old and new names.
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_name_changed(s=%s, name=%s)", s_model, name)
        ev = _event(
            event_name="segm_name_changed",
            s=s_model,
            name=name,
        )
        self._emit(ev)

    def changing_segm_class(self, s: ida_segment.segment_t) -> None:
        """Segment class is being changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("changing_segm_class(s=%s)", s_model)
        ev = _event(event_name="changing_segm_class", s=s_model)
        self._emit(ev)

    def segm_class_changed(self, s: ida_segment.segment_t, sclass: str) -> None:
        """Segment class has been changed."""
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_class_changed(s=%s, sclass=%s)", s_model, sclass)
        ev = _event(
            event_name="segm_class_changed",
            s=s_model,
            sclass=sclass,
        )
        self._emit(ev)

    def segm_attrs_updated(self, s: ida_segment.segment_t) -> None:
        """Segment attributes has been changed.

        This event is generated for secondary segment attributes (examples: color, permissions, etc).
        """
        s_model = SegmentModel.from_segment_t(s)
        logger.debug("segm_attrs_updated(s=%s)", s_model)
        ev = _event(event_name="segm_attrs_updated", s=s_model)
        self._emit(ev)

    def segm_moved(
        self,
        _from: int,
        to: int,
        size: int,
        changed_netmap: bool,
    ) -> None:
        """Segment has been moved.

        See also idb_event::allsegs_moved.
        """
        logger.debug(
            "segm_moved(_from=%d, to=%d, size=%d, changed_netmap=%s)",
            _from,
            to,
            size,
            changed_netmap,
        )
        ev = _event(
            event_name="segm_moved",
            _from=_from,
            to=to,
            size=size,
            changed_netmap=changed_netmap,
        )
        self._emit(ev)

    def allsegs_moved(self, info: ida_moves.segm_move_infos_t) -> None:
        """Program rebasing is complete.

        This event is generated after series of segm_moved events.

        Args:
            info: Segment move information (segm_move_infos_t).
        """
        logger.debug("allsegs_moved(info=%s)", info)
        moves = [
            SegmMoveInfoModel.from_segm_move_info_t(info[i]) for i in range(len(info))
        ]
        ev = _event(event_name="allsegs_moved", moves=moves)
        self._emit(ev)

    ### function operations

    def func_added(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has added a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_added(pfn=%s)", pfn_model)
        ev = _event(event_name="func_added", pfn=pfn_model)
        self._emit(ev)

    def func_updated(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has updated a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_updated(pfn=%s)", pfn_model)
        ev = _event(event_name="func_updated", pfn=pfn_model)
        self._emit(ev)

    def set_func_start(self, pfn: ida_funcs.func_t, new_start: int) -> None:
        """Function chunk start address will be changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug(
            "set_func_start(pfn=%s, new_start=%d)",
            pfn_model,
            new_start,
        )
        ev = _event(
            event_name="set_func_start",
            pfn=pfn_model,
            new_start=new_start,
        )
        self._emit(ev)

    def set_func_end(self, pfn: ida_funcs.func_t, new_end: int) -> None:
        """Function chunk end address will be changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("set_func_end(pfn=%s, new_end=%d)", pfn_model, new_end)
        ev = _event(
            event_name="set_func_end",
            pfn=pfn_model,
            new_end=new_end,
        )
        self._emit(ev)

    def deleting_func(self, pfn: ida_funcs.func_t) -> None:
        """The kernel is about to delete a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("deleting_func(pfn=%s)", pfn_model)
        if pfn_model.name:
            self._pending_delete_func_names[pfn.start_ea] = pfn_model.name
        ev = _event(event_name="deleting_func", pfn=pfn_model)
        self._emit(ev)

    def func_deleted(self, func_ea: int) -> None:
        """A function has been deleted."""
        logger.debug("func_deleted(func_ea=%d)", func_ea)
        func_name = self._pending_delete_func_names.pop(func_ea, None)
        ev = _event(
            event_name="func_deleted",
            func_ea=func_ea,
            func_name=func_name,
        )
        self._emit(ev)

    def thunk_func_created(self, pfn: ida_funcs.func_t) -> None:
        """A thunk bit has been set for a function."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("thunk_func_created(pfn=%s)", pfn_model)
        ev = _event(event_name="thunk_func_created", pfn=pfn_model)
        self._emit(ev)

    def func_tail_appended(self, pfn: ida_funcs.func_t, tail: ida_funcs.func_t) -> None:
        """A function tail chunk has been appended."""
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = FuncModel.from_func_t(tail)
        logger.debug(
            "func_tail_appended(pfn=%s, tail=%s)",
            pfn_model,
            tail_model,
        )
        ev = _event(
            event_name="func_tail_appended",
            pfn=pfn_model,
            tail=tail_model,
        )
        self._emit(ev)

    def deleting_func_tail(
        self, pfn: ida_funcs.func_t, tail: ida_range.range_t
    ) -> None:
        """A function tail chunk is to be removed."""
        pfn_model = FuncModel.from_func_t(pfn)
        tail_model = RangeModel.from_range_t(tail)
        logger.debug(
            "deleting_func_tail(pfn=%s, tail=%s)",
            pfn_model,
            tail_model,
        )
        ev = _event(
            event_name="deleting_func_tail",
            pfn=pfn_model,
            tail=tail_model,
        )
        self._emit(ev)

    def func_tail_deleted(self, pfn: ida_funcs.func_t, tail_ea: int) -> None:
        """A function tail chunk has been removed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug(
            "func_tail_deleted(pfn=%s, tail_ea=%d)",
            pfn_model,
            tail_ea,
        )
        ev = _event(
            event_name="func_tail_deleted",
            pfn=pfn_model,
            tail_ea=tail_ea,
        )
        self._emit(ev)

    def tail_owner_changed(
        self,
        tail: ida_funcs.func_t,
        owner_func: int,
        old_owner: int,
    ) -> None:
        """A tail chunk owner has been changed."""
        tail_model = FuncModel.from_func_t(tail)
        logger.debug(
            "tail_owner_changed(tail=%s, owner_func=%d, old_owner=%d)",
            tail_model,
            owner_func,
            old_owner,
        )
        ev = _event(
            event_name="tail_owner_changed",
            tail=tail_model,
            owner_func=owner_func,
            old_owner=old_owner,
        )
        self._emit(ev)

    def func_noret_changed(self, pfn: ida_funcs.func_t) -> None:
        """FUNC_NORET bit has been changed."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("func_noret_changed(pfn=%s)", pfn_model)
        ev = _event(event_name="func_noret_changed", pfn=pfn_model)
        self._emit(ev)

    def updating_tryblks(self, tbv) -> None:
        """About to update tryblk information."""
        tryblks = [TryblkModel.from_tryblk_t(tb) for tb in tbv]
        logger.debug("updating_tryblks(tryblks=%s)", tryblks)
        ev = _event(event_name="updating_tryblks", tryblks=tryblks)
        self._emit(ev)

    def tryblks_updated(self, tbv) -> None:
        """Updated tryblk information."""
        tryblks = [TryblkModel.from_tryblk_t(tb) for tb in tbv]
        logger.debug("tryblks_updated(tryblks=%s)", tryblks)
        ev = _event(event_name="tryblks_updated", tryblks=tryblks)
        self._emit(ev)

    def deleting_tryblks(self, range: ida_range.range_t) -> None:
        """About to delete tryblk information in given range."""
        range_model = RangeModel.from_range_t(range)
        logger.debug("deleting_tryblks(range=%s)", range_model)
        ev = _event(event_name="deleting_tryblks", range=range_model)
        self._emit(ev)

    ### comments

    def changing_cmt(self, ea: int, repeatable_cmt: bool, newcmt: str) -> None:
        """An item comment is to be changed."""
        logger.debug(
            "changing_cmt(ea=%d, repeatable_cmt=%s, newcmt=%s)",
            ea,
            repeatable_cmt,
            newcmt,
        )
        ev = _event(
            event_name="changing_cmt",
            ea=ea,
            repeatable_cmt=repeatable_cmt,
            newcmt=newcmt,
        )
        self._emit(ev)

    def cmt_changed(self, ea: int, repeatable_cmt: bool) -> None:
        """An item comment has been changed."""
        logger.debug("cmt_changed(ea=%d, repeatable_cmt=%s)", ea, repeatable_cmt)
        ev = _event(
            event_name="cmt_changed",
            ea=ea,
            repeatable_cmt=repeatable_cmt,
        )
        self._emit(ev)

    def changing_range_cmt(
        self, kind, a: ida_range.range_t, cmt: str, repeatable: bool
    ) -> None:
        """Range comment is to be changed."""
        a_model = RangeModel.from_range_t(a)
        logger.debug(
            "changing_range_cmt(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model,
            cmt,
            repeatable,
        )
        ev = _event(
            event_name="changing_range_cmt",
            kind=kind,
            a=a_model,
            cmt=cmt,
            repeatable=repeatable,
        )
        self._emit(ev)

    def range_cmt_changed(
        self, kind, a: ida_range.range_t, cmt: str, repeatable: bool
    ) -> None:
        """Range comment has been changed."""
        a_model = RangeModel.from_range_t(a)
        logger.debug(
            "range_cmt_changed(kind=%s, a=%s, cmt=%s, repeatable=%s)",
            kind,
            a_model,
            cmt,
            repeatable,
        )
        ev = _event(
            event_name="range_cmt_changed",
            kind=kind,
            a=a_model,
            cmt=cmt,
            repeatable=repeatable,
        )
        self._emit(ev)

    def extra_cmt_changed(self, ea: int, line_idx: int, cmt: str) -> None:
        """An extra comment has been changed."""
        logger.debug("extra_cmt_changed(ea=%d, line_idx=%d, cmt=%s)", ea, line_idx, cmt)
        ev = _event(
            event_name="extra_cmt_changed",
            ea=ea,
            line_idx=line_idx,
            cmt=cmt,
        )
        self._emit(ev)

    ### item operations

    def sgr_changed(
        self,
        start_ea: int,
        end_ea: int,
        regnum: int,
        value,
        old_value,
        tag: int,
    ) -> None:
        """The kernel has changed a segment register value."""
        logger.debug(
            "sgr_changed(start_ea=%d, end_ea=%d, regnum=%d, value=%s, old_value=%s, tag=%d)",
            start_ea,
            end_ea,
            regnum,
            value,
            old_value,
            tag,
        )
        ev = _event(
            event_name="sgr_changed",
            start_ea=start_ea,
            end_ea=end_ea,
            regnum=regnum,
            value=value,
            old_value=old_value,
            tag=tag,
        )
        self._emit(ev)

    def sgr_deleted(self, start_ea: int, end_ea: int, regnum: int) -> None:
        """The kernel has deleted a segment register value."""
        logger.debug(
            "sgr_deleted(start_ea=%d, end_ea=%d, regnum=%d)", start_ea, end_ea, regnum
        )
        ev = _event(
            event_name="sgr_deleted",
            start_ea=start_ea,
            end_ea=end_ea,
            regnum=regnum,
        )
        self._emit(ev)

    def make_code(self, insn: ida_ua.insn_t) -> None:
        """An instruction is being created."""
        insn_model = InsnModel.from_insn_t(insn)
        logger.debug("make_code(insn=%s)", insn_model)
        ev = _event(event_name="make_code", insn=insn_model)
        self._emit(ev)

    def make_data(self, ea: int, flags: int, tid: int, len: int) -> None:
        """A data item is being created."""
        logger.debug("make_data(ea=%d, flags=%d, tid=%d, len=%d)", ea, flags, tid, len)
        tif = ida_typeinf.tinfo_t()
        if tif.get_type_by_tid(tid):
            type_name = tif.get_type_name() or "(unnamed)"
        else:
            type_name = "(unnamed)"
        ev = _event(
            event_name="make_data",
            ea=ea,
            flags=flags,
            type_name=type_name,
            len=len,
        )
        self._emit(ev)

    def destroyed_items(self, ea1: int, ea2: int, will_disable_range: bool) -> None:
        """Instructions/data have been destroyed in [ea1,ea2)."""
        logger.debug(
            "destroyed_items(ea1=%d, ea2=%d, will_disable_range=%s)",
            ea1,
            ea2,
            will_disable_range,
        )
        ev = _event(
            event_name="destroyed_items",
            ea1=ea1,
            ea2=ea2,
            will_disable_range=will_disable_range,
        )
        self._emit(ev)

    def renamed(self, ea: int, new_name: str, local_name: bool, old_name: str) -> None:
        """The kernel has renamed a byte.

        See also the rename event."""
        logger.debug(
            "renamed(ea=%d, new_name=%s, local_name=%s, old_name=%s)",
            ea,
            new_name,
            local_name,
            old_name,
        )
        ev = _event(
            event_name="renamed",
            ea=ea,
            new_name=new_name,
            local_name=local_name,
            old_name=old_name,
        )
        self._emit(ev)

    def byte_patched(self, ea: int, old_value: int) -> None:
        """A byte has been patched."""
        logger.debug("byte_patched(ea=%d, old_value=%d)", ea, old_value)
        ev = _event(
            event_name="byte_patched",
            ea=ea,
            old_value=old_value,
        )
        self._emit(ev)

    def item_color_changed(self, ea: int, color) -> None:
        """An item color has been changed.

        If color==DEFCOLOR, then the color is deleted."""
        logger.debug("item_color_changed(ea=%d, color=%s)", ea, color)
        ev = _event(
            event_name="item_color_changed",
            ea=ea,
            color=color,
        )
        self._emit(ev)

    def callee_addr_changed(self, ea: int, callee: int) -> None:
        """Callee address has been updated by the user."""
        logger.debug("callee_addr_changed(ea=%d, callee=%d)", ea, callee)
        ev = _event(
            event_name="callee_addr_changed",
            ea=ea,
            callee=callee,
        )
        self._emit(ev)

    def bookmark_changed(
        self, index: int, pos: ida_moves.lochist_entry_t, desc: str, operation: int
    ) -> None:
        """Bookmarked position changed.

        If desc==None, then the bookmark was deleted."""
        try:
            ea = pos.place().toea()
        except Exception:  # noqa: BLE001 - invalid bookmark positions are observable
            ea = None
        logger.debug(
            "bookmark_changed(index=%d, ea=%s, desc=%s, operation=%d)",
            index,
            ea,
            desc,
            operation,
        )
        ev = _event(
            event_name="bookmark_changed",
            index=index,
            ea=ea,
            desc=desc,
            operation=operation,
        )
        self._emit(ev)

    def changing_op_type(self, ea: int, n: int, opinfo) -> None:
        """An operand type (offset, hex, etc...) is to be changed."""
        logger.debug("changing_op_type(ea=%d, n=%d, opinfo=%s)", ea, n, opinfo)
        opinfo_model = OpInfoModel.from_opinfo_t(opinfo)
        ev = _event(
            event_name="changing_op_type",
            ea=ea,
            n=n,
            opinfo=opinfo_model,
        )
        self._emit(ev)

    def op_type_changed(self, ea: int, n: int) -> None:
        """An operand type (offset, hex, etc...) has been set or deleted.

        Args:
            ea: Address.
            n: Operand number, eventually or'ed with OPND_OUTER or OPND_ALL.
        """
        logger.debug("op_type_changed(ea=%d, n=%d)", ea, n)
        try:
            opinfo_model = OpInfoModel.from_database(ea, n)
        except Exception:
            logger.exception("Failed to get opinfo from database")
            opinfo_model = None
        ev = _event(
            event_name="op_type_changed",
            ea=ea,
            n=n,
            opinfo=opinfo_model,
        )
        self._emit(ev)

    ### dirtree

    def dirtree_mkdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been created."""
        logger.debug("dirtree_mkdir(path=%s)", path)
        ev = _event(event_name="dirtree_mkdir", path=path)
        self._emit(ev)

    def dirtree_rmdir(self, dt: ida_dirtree.dirtree_t, path: str) -> None:
        """Dirtree: a directory has been deleted."""
        logger.debug("dirtree_rmdir(path=%s)", path)
        ev = _event(event_name="dirtree_rmdir", path=path)
        self._emit(ev)

    def dirtree_link(self, dt: ida_dirtree.dirtree_t, path: str, link: bool) -> None:
        """Dirtree: an item has been linked/unlinked."""
        logger.debug("dirtree_link(path=%s, link=%s)", path, link)
        ev = _event(event_name="dirtree_link", path=path, link=link)
        self._emit(ev)

    def dirtree_move(self, dt: ida_dirtree.dirtree_t, _from: str, to: str) -> None:
        """Dirtree: a directory or item has been moved."""
        logger.debug("dirtree_move(_from=%s, to=%s)", _from, to)
        ev = _event(event_name="dirtree_move", _from=_from, to=to)
        self._emit(ev)

    def dirtree_rank(self, dt: ida_dirtree.dirtree_t, path: str, rank: int) -> None:
        """Dirtree: a directory or item rank has been changed."""
        logger.debug("dirtree_rank(path=%s, rank=%d)", path, rank)
        ev = _event(event_name="dirtree_rank", path=path, rank=rank)
        self._emit(ev)

    def dirtree_rminode(self, dt: ida_dirtree.dirtree_t, inode: int) -> None:
        """Dirtree: an inode became unavailable."""
        logger.debug("dirtree_rminode(inode=%d)", inode)
        ev = _event(event_name="dirtree_rminode", inode=inode)
        self._emit(ev)

    def dirtree_segm_moved(self, dt: ida_dirtree.dirtree_t) -> None:
        """Dirtree: inodes were changed due to a segment movement or a program rebasing."""
        logger.debug("dirtree_segm_moved()")
        ev = _event(event_name="dirtree_segm_moved")
        self._emit(ev)

    ### types

    def changing_ti(
        self,
        ea: int,
        new_type: bytes,
        new_fnames: bytes,
    ) -> None:
        """An item typestring (C/C++ prototype) is to be changed."""
        logger.debug(
            "changing_ti(ea=%d, new_type=%s, new_fnames=%s)", ea, new_type, new_fnames
        )
        new_type_str = deserialize_type_to_str(new_type, new_fnames)
        ev = _event(
            event_name="changing_ti",
            ea=ea,
            new_type=new_type,
            new_fnames=new_fnames,
            new_type_str=new_type_str,
        )
        self._emit(ev)

    def ti_changed(self, ea: int, type: bytes, fnames: bytes) -> None:
        """An item typestring (C/C++ prototype) has been changed."""
        logger.debug("ti_changed(ea=%d, type=%s, fnames=%s)", ea, type, fnames)
        type_str = deserialize_type_to_str(type, fnames)
        ev = _event(
            event_name="ti_changed",
            ea=ea,
            type=type,
            fnames=fnames,
            type_str=type_str,
        )
        self._emit(ev)

    def changing_op_ti(
        self,
        ea: int,
        n: int,
        new_type: bytes,
        new_fnames: bytes,
    ) -> None:
        """An operand typestring (c/c++ prototype) is to be changed."""
        logger.debug(
            "changing_op_ti(ea=%d, n=%d, new_type=%s, new_fnames=%s)",
            ea,
            n,
            new_type,
            new_fnames,
        )
        new_type_str = deserialize_type_to_str(new_type, new_fnames)
        ev = _event(
            event_name="changing_op_ti",
            ea=ea,
            n=n,
            new_type=new_type,
            new_fnames=new_fnames,
            new_type_str=new_type_str,
        )
        self._emit(ev)

    def op_ti_changed(
        self,
        ea: int,
        n: int,
        type: bytes,
        fnames: bytes,
    ) -> None:
        """An operand typestring (c/c++ prototype) has been changed."""
        logger.debug(
            "op_ti_changed(ea=%d, n=%d, type=%s, fnames=%s)", ea, n, type, fnames
        )
        type_str = deserialize_type_to_str(type, fnames)
        ev = _event(
            event_name="op_ti_changed",
            ea=ea,
            n=n,
            type=type,
            fnames=fnames,
            type_str=type_str,
        )
        self._emit(ev)

    ### local types

    def local_types_changed(self, ltc, ordinal: int, name: str) -> None:
        """Local types have been changed.

        Args:
            ltc (local_type_change_t): integer enum value
            ordinal: 0 means ordinal is unknown
            name: nullptr means name is unknown
        """
        try:
            ltc_enum = LocalTypeChange(ltc)
        except ValueError:
            return
        logger.debug(
            "local_types_changed(ltc=%s, ordinal=%d, name=%s)",
            ltc_enum.name,
            ordinal,
            name,
        )
        ev = _event(
            event_name="local_types_changed",
            ltc=ltc_enum,
            ordinal=ordinal,
            name=name,
        )
        self._emit(ev)

    def lt_udm_created(self, udtname: str, udm: ida_typeinf.udm_t) -> None:
        """Local type udt member has been added."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug("lt_udm_created(udtname=%s, udm=%s)", udtname, udm_model)
        ev = _event(
            event_name="lt_udm_created",
            udtname=udtname,
            udm=udm_model,
        )
        self._emit(ev)

    def lt_udm_deleted(
        self, udtname: str, udm_tid: int, udm: ida_typeinf.udm_t
    ) -> None:
        """Local type udt member has been deleted."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug(
            "lt_udm_deleted(udtname=%s, udm_tid=%d, udm=%s)",
            udtname,
            udm_tid,
            udm_model,
        )
        ev = _event(
            event_name="lt_udm_deleted",
            udtname=udtname,
            udm=udm_model,
        )
        self._emit(ev)

    def lt_udm_renamed(
        self, udtname: str, udm: ida_typeinf.udm_t, oldname: str
    ) -> None:
        """Local type udt member has been renamed."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug(
            "lt_udm_renamed(udtname=%s, udm=%s, oldname=%s)",
            udtname,
            udm_model,
            oldname,
        )
        ev = _event(
            event_name="lt_udm_renamed",
            udtname=udtname,
            udm=udm_model,
            oldname=oldname,
        )
        self._emit(ev)

    def lt_udm_changed(
        self,
        udtname: str,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Local type udt member has been changed."""
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.debug(
            "lt_udm_changed(udtname=%s, udm_tid=%d, udmold=%s, udmnew=%s)",
            udtname,
            udm_tid,
            udmold_model,
            udmnew_model,
        )
        ev = _event(
            event_name="lt_udm_changed",
            udtname=udtname,
            udmold=udmold_model,
            udmnew=udmnew_model,
        )
        self._emit(ev)

    def lt_udt_expanded(self, udtname: str, udm_tid: int, delta: int) -> None:
        """A structure type has been expanded/shrank.

        Args:
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.debug(
            "lt_udt_expanded(udtname=%s, udm_tid=%d, delta=%d)", udtname, udm_tid, delta
        )
        tif = ida_typeinf.tinfo_t()
        tif.get_named_type(None, udtname)
        udm = ida_typeinf.udm_t()
        idx = tif.get_udm_by_tid(udm, udm_tid)
        udm_name = udm.name if idx >= 0 else "(unnamed)"
        ev = _event(
            event_name="lt_udt_expanded",
            udtname=udtname,
            udm_name=udm_name,
            delta=delta,
        )
        self._emit(ev)

    def lt_edm_created(self, enumname: str, edm: ida_typeinf.edm_t) -> None:
        """Local type enum member has been added."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.debug("lt_edm_created(enumname=%s, edm=%s)", enumname, edm_model)
        ev = _event(
            event_name="lt_edm_created",
            enumname=enumname,
            edm=edm_model,
        )
        self._emit(ev)

    def lt_edm_deleted(
        self, enumname: str, edm_tid: int, edm: ida_typeinf.edm_t
    ) -> None:
        """Local type enum member has been deleted."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.debug(
            "lt_edm_deleted(enumname=%s, edm_tid=%d, edm=%s)",
            enumname,
            edm_tid,
            edm_model,
        )
        ev = _event(
            event_name="lt_edm_deleted",
            enumname=enumname,
            edm=edm_model,
        )
        self._emit(ev)

    def lt_edm_renamed(
        self, enumname: str, edm: ida_typeinf.edm_t, oldname: str
    ) -> None:
        """Local type enum member has been renamed."""
        edm_model = EdmModel.from_edm_t(edm)
        logger.debug(
            "lt_edm_renamed(enumname=%s, edm=%s, oldname=%s)",
            enumname,
            edm_model,
            oldname,
        )
        ev = _event(
            event_name="lt_edm_renamed",
            enumname=enumname,
            edm=edm_model,
            oldname=oldname,
        )
        self._emit(ev)

    def lt_edm_changed(
        self,
        enumname: str,
        edm_tid: int,
        edmold: ida_typeinf.edm_t,
        edmnew: ida_typeinf.edm_t,
    ) -> None:
        """Local type enum member has been changed."""
        edmold_model = EdmModel.from_edm_t(edmold)
        edmnew_model = EdmModel.from_edm_t(edmnew)
        logger.debug(
            "lt_edm_changed(enumname=%s, edm_tid=%d, edmold=%s, edmnew=%s)",
            enumname,
            edm_tid,
            edmold_model,
            edmnew_model,
        )
        ev = _event(
            event_name="lt_edm_changed",
            enumname=enumname,
            edmold=edmold_model,
            edmnew=edmnew_model,
        )
        self._emit(ev)

    ### frames

    def stkpnts_changed(self, pfn: ida_funcs.func_t) -> None:
        """Stack change points have been modified."""
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("stkpnts_changed(pfn=%s)", pfn_model)
        ev = _event(event_name="stkpnts_changed", pfn=pfn_model)
        self._emit(ev)

    def frame_created(self, func_ea: int) -> None:
        """A function frame has been created.

        See also idb_event::frame_deleted.
        """
        logger.debug("frame_created(func_ea=%d)", func_ea)
        func_name = ida_funcs.get_func_name(func_ea)
        ev = _event(
            event_name="frame_created",
            func_ea=func_ea,
            func_name=func_name if func_name else None,
        )
        self._emit(ev)

    def frame_expanded(self, func_ea: int, udm_tid: int, delta: int) -> None:
        """A frame type has been expanded/shrank.

        Args:
            udm_tid: The gap was added/removed before this member.
            delta: Number of added/removed bytes.
        """
        logger.debug(
            "frame_expanded(func_ea=%d, udm_tid=%d, delta=%d)", func_ea, udm_tid, delta
        )
        func_name = ida_funcs.get_func_name(func_ea)
        frame_tif = ida_typeinf.tinfo_t()
        ida_frame.get_func_frame(frame_tif, ida_funcs.get_func(func_ea))
        udm = ida_typeinf.udm_t()
        idx = frame_tif.get_udm_by_tid(udm, udm_tid)
        udm_name = udm.name if idx >= 0 else "(unnamed)"
        ev = _event(
            event_name="frame_expanded",
            func_ea=func_ea,
            func_name=func_name if func_name else None,
            udm_name=udm_name,
            delta=delta,
        )
        self._emit(ev)

    def frame_deleted(self, pfn: ida_funcs.func_t) -> None:
        """The kernel has deleted a function frame.

        See also idb_event::frame_created.
        """
        pfn_model = FuncModel.from_func_t(pfn)
        logger.debug("frame_deleted(pfn=%s)", pfn_model)
        ev = _event(event_name="frame_deleted", pfn=pfn_model)
        self._emit(ev)

    def frame_udm_created(self, func_ea: int, udm: ida_typeinf.udm_t) -> None:
        """Frame member has been added."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug(
            "frame_udm_created(func_ea=%d, udm=%s)",
            func_ea,
            udm_model,
        )
        func_name = ida_funcs.get_func_name(func_ea)
        ev = _event(
            event_name="frame_udm_created",
            func_ea=func_ea,
            func_name=func_name if func_name else None,
            udm=udm_model,
        )
        self._emit(ev)

    def frame_udm_deleted(
        self, func_ea: int, udm_tid: int, udm: ida_typeinf.udm_t
    ) -> None:
        """Frame member has been deleted."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug(
            "frame_udm_deleted(func_ea=%d, udm_tid=%d, udm=%s)",
            func_ea,
            udm_tid,
            udm_model,
        )
        func_name = ida_funcs.get_func_name(func_ea)
        ev = _event(
            event_name="frame_udm_deleted",
            func_ea=func_ea,
            func_name=func_name if func_name else None,
            udm=udm_model,
        )
        self._emit(ev)

    def frame_udm_renamed(
        self, func_ea: int, udm: ida_typeinf.udm_t, oldname: str
    ) -> None:
        """Frame member has been renamed."""
        udm_model = UdmModel.from_udm_t(udm)
        logger.debug(
            "frame_udm_renamed(func_ea=%d, udm=%s, oldname=%s)",
            func_ea,
            udm_model,
            oldname,
        )
        func_name = ida_funcs.get_func_name(func_ea)
        ev = _event(
            event_name="frame_udm_renamed",
            func_ea=func_ea,
            func_name=func_name if func_name else None,
            udm=udm_model,
            oldname=oldname,
        )
        self._emit(ev)

    def frame_udm_changed(
        self,
        func_ea: int,
        udm_tid: int,
        udmold: ida_typeinf.udm_t,
        udmnew: ida_typeinf.udm_t,
    ) -> None:
        """Frame member has been changed."""
        udmold_model = UdmModel.from_udm_t(udmold)
        udmnew_model = UdmModel.from_udm_t(udmnew)
        logger.debug(
            "frame_udm_changed(func_ea=%d, udm_tid=%d, udmold=%s, udmnew=%s)",
            func_ea,
            udm_tid,
            udmold_model,
            udmnew_model,
        )
        func_name = ida_funcs.get_func_name(func_ea)
        ev = _event(
            event_name="frame_udm_changed",
            func_ea=func_ea,
            func_name=func_name if func_name else None,
            udmold=udmold_model,
            udmnew=udmnew_model,
        )
        self._emit(ev)
