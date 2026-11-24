"""Public lifecycle, project, analysis, and transaction operations."""

from __future__ import annotations

import base64
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from agenticghidra_mcp.telemetry import METRICS, measure

from .core import address, json_value, operation, page


def _session(call, context, info, read_only, update_analysis):
    call.runtime._attach_indexing(context)
    session = call.runtime.registry.add(context, info, call.owner, read_only)
    try:
        with call.runtime.program_lock(info.program):
            call.runtime.guard(session, call.owner)
            call.runtime.adopt_program(context, info.program)
            if update_analysis:
                # Read-only controls subsequent client edits, not initial import analysis.
                before = info.ghidra_analysis_complete
                tx = info.program.startTransaction("Initial MCP analysis")
                try:
                    call.runtime.analyze(session, call.monitor)
                except BaseException:
                    info.program.endTransaction(tx, False)
                    info.ghidra_analysis_complete = before
                    call.runtime.invalidate(session)
                    raise
                else:
                    info.program.endTransaction(tx, True)
                    call.runtime.invalidate(session)
            return session.describe()
    except BaseException:
        call.runtime.registry.sessions.pop(session.session_id, None)
        raise


def _root(context):
    return context.project.getProjectData().getRootFolder()


def _project(context):
    project = context.project
    return project.getProject() if hasattr(project, "getProject") else project


def _open_program(call, context, path):
    from java.lang import Object

    domain = context.project.getProjectData().getFile(path)
    if domain is None:
        raise ValueError(f"Project program not found: {path}")
    consumer = Object()
    program = domain.getDomainObject(consumer, True, False, call.monitor)
    call.runtime.own_program(context, program, consumer)
    if hasattr(context.project, "openProgram"):
        return program
    # Make the database visible to the GUI's existing ownership/refresh machinery.
    from ghidra.app.services import ProgramManager
    from java.util import List

    manager = context._get_primary_program_manager(required=False)
    if manager is None:
        tool = context.project.getToolServices().launchDefaultTool(List.of(domain))
        manager = tool.getService(ProgramManager)
    if manager is None:
        raise RuntimeError("Ghidra GUI did not provide a ProgramManager")
    context.run_on_swing(lambda: manager.openProgram(program, ProgramManager.OPEN_VISIBLE))
    return program


def _save(call, program):
    with measure("save"):
        program.getDomainFile().save(call.monitor)


def _folder(call, path):
    folder = (
        _root(call.context)
        if path == "/"
        else call.context.project.getProjectData().getFolder(path)
    )
    if folder is None:
        raise ValueError(f"Project folder not found: {path}")
    return folder


def _files(folder, recursive=False):
    yield from folder.getFiles()
    if recursive:
        for child in folder.getFolders():
            yield from _files(child, True)


def _file_info(item):
    return {
        "name": str(item.getName()),
        "path": str(item.getPathname()),
        "content_type": str(item.getContentType()),
        "length": int(item.length()),
        "read_only": bool(item.isReadOnly()),
        "version": int(item.getVersion()),
    }


def _options(call):
    return call.program.getOptions("Analyzers")


def _option(call, name):
    options = _options(call)
    if not options.contains(name):
        raise ValueError(f"Unknown analysis option: {name}")
    return options


_SCALAR_OPTIONS = {
    "BOOLEAN_TYPE": ("Boolean", False, bool),
    "INT_TYPE": ("Int", 0, int),
    "LONG_TYPE": ("Long", 0, int),
    "FLOAT_TYPE": ("Float", 0.0, float),
    "DOUBLE_TYPE": ("Double", 0.0, float),
}

_OPTION_VALUES = {
    "DATE_TYPE": lambda value: int(value.getTime()),
    "ENUM_TYPE": lambda value: str(value.name()),
    "BYTE_ARRAY_TYPE": lambda value: base64.b64encode(
        bytes((int(item) & 255) for item in value)
    ).decode(),
    "FILE_TYPE": lambda value: str(value.getPath()),
    "STRING_TYPE": str,
}


def _option_value(options, name):
    option_type = options.getType(name)
    kind = str(option_type.name())
    scalar = _SCALAR_OPTIONS.get(kind)
    if scalar is not None:
        suffix, default, convert = scalar
        return convert(getattr(options, "get" + suffix)(name, default))
    value = options.getObject(name, None)
    if value is None:
        return None
    convert = _OPTION_VALUES.get(kind)
    if convert is not None:
        return convert(value)
    return str(option_type.convertObjectToString(value))


@operation("health.ping", api="ghidra.framework.Application", program=False)
def health_ping(call):
    from ghidra.framework import Application

    return {
        "status": "ok",
        "ghidra_version": str(Application.getApplicationVersion()),
        "metrics": METRICS.snapshot(),
        **call.runtime.busy_status(),
    }


@operation("mcp.response_format", api="MCP structured result contract", program=False)
def response_format(call):
    return {
        "format": "json",
        "addresses": "hexadecimal strings",
        "pagination": {"offset": 0, "limit": 100, "maximum_limit": 1000},
        "sessions": "Opaque identifiers bound to the requesting MCP connection",
        "errors": "MCP tool errors",
    }


def _existing_program(context, path, source, program_name, hinted):
    info = context._lookup_program_info(path)
    if info is None and not hinted:
        info = next(
            (
                item
                for item in context.programs.values()
                if str(item.program.getExecutablePath()) == str(source)
                and (program_name is None or str(item.program.getName()) == program_name)
            ),
            None,
        )
    if info is not None:
        if hinted:
            raise ValueError(
                "Loader/language/compiler hints apply to imports, not already loaded programs"
            )
        if program_name is not None and str(info.program.getName()) != program_name:
            raise ValueError("program_name differs from the already loaded program")
    return info


def _initialize_analyzer_options(program):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    transaction = program.startTransaction("Initialize MCP analyzer options")
    try:
        AutoAnalysisManager.getAnalysisManager(program).initializeOptions()
    except BaseException:
        program.endTransaction(transaction, False)
        raise
    else:
        program.endTransaction(transaction, True)


def _import_program(call, context, source, import_name, language, compiler, loader):
    from ghidra.app.util.importer import ProgramLoader
    from java.io import File

    builder = (
        ProgramLoader.builder()
        .source(File(str(source)))
        .project(_project(context))
        .monitor(call.monitor)
    )
    for method, value in (("language", language), ("compiler", compiler), ("loaders", loader)):
        if value is not None:
            getattr(builder, method)(value)
    builder.name(import_name)
    with measure("import"):
        loaded = builder.load()
    try:
        loaded.save(call.monitor)
        domain = loaded.getPrimary().getSavedDomainFile()
        if domain is None:
            raise RuntimeError("Loader did not save the primary program")
        binary_path = str(domain.getPathname())
    finally:
        loaded.close()
    program = _open_program(call, context, binary_path)
    _initialize_analyzer_options(program)
    info = context._init_program_info(program)
    context.programs[binary_path] = info
    return info


@operation("program.open", kind="project", api="ProgramLoader.Builder", program=False)
def program_open(
    call,
    path,
    update_analysis=True,
    read_only=True,
    project_location=None,
    project_name=None,
    program_name=None,
    language=None,
    compiler=None,
    loader=None,
):
    context = call.runtime.registry.project_context(project_location, project_name)
    call.runtime._attach_indexing(context)
    source = Path(path).expanduser().resolve()
    hinted = any(value is not None for value in (language, compiler, loader))
    info = _existing_program(context, path, source, program_name, hinted)
    if info is not None:
        return _session(call, context, info, read_only, update_analysis)
    # Keep content-derived naming for repeated opens, including temporary
    # open_bytes sources whose original pathname is gone.
    if not source.is_file():
        raise FileNotFoundError(f"Binary file not found: {source}")
    from agenticghidra_mcp.context import PyGhidraContext

    import_name = program_name or PyGhidraContext._gen_unique_bin_name(source)
    if program_name is None:
        info = context._lookup_program_info(import_name)
        if info is not None and hinted:
            raise ValueError("Hints require a new import; use a distinct program_name")
    if info is None:
        info = _import_program(call, context, source, import_name, language, compiler, loader)
    return _session(call, context, info, read_only, update_analysis)


@operation("program.open_bytes", kind="project", api="ProgramLoader.Builder", program=False)
def program_open_bytes(
    call,
    data_base64,
    filename="session.bin",
    update_analysis=True,
    read_only=True,
    project_location=None,
    project_name=None,
    program_name=None,
    language=None,
    compiler=None,
    loader=None,
):
    data = base64.b64decode(data_base64, validate=True)
    if not data:
        raise ValueError("Program bytes must not be empty")
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise ValueError("filename must be a single file name")
    with tempfile.TemporaryDirectory(prefix="ghidra-mcp-import-") as directory:
        source = Path(directory) / filename
        source.write_bytes(data)
        return program_open(
            call,
            str(source),
            update_analysis,
            read_only,
            project_location,
            project_name,
            program_name,
            language,
            compiler,
            loader,
        )


@operation("program.list_open", api="ProgramRegistry", program=False)
def program_list_open(call):
    return {
        "programs": [
            session.describe()
            for session in list(call.runtime.registry.sessions.values())
            if session.owner == call.owner
        ]
    }


@operation("program.close", kind="project", api="ProgramRegistry session release")
def program_close(call):
    call.runtime.guard(call.session, call.owner, no_pending=True)
    if any(
        task.session.session_id == call.session.session_id
        and (task.future is None or not task.future.done())
        for task in list(call.runtime._tasks.values())
    ):
        raise RuntimeError("Cancel and wait for this session's tasks before closing it")
    call.runtime.registry.sessions.pop(call.session.session_id)
    return {"closed": True, "session_id": call.session.session_id}


@operation("program.mode.get", api="ProgramRegistry session mode")
def program_mode_get(call):
    return {"read_only": call.session.read_only, "deterministic": call.session.deterministic}


@operation("program.mode.set", kind="project", api="ProgramRegistry session mode")
def program_mode_set(call, read_only=None, deterministic=None):
    call.runtime.guard(call.session, call.owner, no_pending=True)
    if read_only is not None:
        call.session.read_only = bool(read_only)
    if deterministic is not None:
        call.session.deterministic = bool(deterministic)
    return program_mode_get(call)


@operation("program.summary", api="Program, FunctionManager, Memory")
def program_summary(call):
    p = call.program
    return {
        **call.session.describe(),
        "language": str(p.getLanguageID()),
        "compiler": str(p.getCompilerSpec().getCompilerSpecID()),
        "image_base": str(p.getImageBase()),
        "min_address": str(p.getMinAddress()),
        "max_address": str(p.getMaxAddress()),
        "executable_format": str(p.getExecutableFormat()),
        "executable_path": str(p.getExecutablePath()),
        "function_count": int(p.getFunctionManager().getFunctionCount()),
        "memory_size": int(p.getMemory().getSize()),
        "changed": bool(p.isChanged()),
        "analysis_complete": call.info.analysis_complete,
    }


@operation("program.report", api="Program.getMetadata, getOptions")
def program_report(call):
    return {
        **program_summary(call),
        "metadata": json_value(dict(call.program.getMetadata())),
        "memory_blocks": [
            {
                "name": str(b.getName()),
                "start": str(b.getStart()),
                "end": str(b.getEnd()),
                "size": int(b.getSize()),
                "read": bool(b.isRead()),
                "write": bool(b.isWrite()),
                "execute": bool(b.isExecute()),
            }
            for b in call.program.getMemory().getBlocks()
        ],
    }


@operation("program.save", kind="project", api="DomainFile.save")
def program_save(call):
    call.runtime.guard(call.session, call.owner, write=True, no_pending=True)
    _save(call, call.program)
    return {"saved": True, "path": str(call.program.getDomainFile().getPathname())}


@operation("program.save_as", kind="project", api="DomainFolder.createFile")
def program_save_as(call, program_name, folder_path="/", overwrite=True):
    call.runtime.guard(call.session, call.owner, write=True, no_pending=True)
    _folder(call, folder_path)
    if not program_name or "/" in program_name:
        raise ValueError("program_name must be a single project file name")
    old_path = str(call.program.getDomainFile().getPathname())
    with measure("save"):
        target = _folder(call, folder_path)
        existing = target.getFile(program_name)
        if existing is not None and str(existing.getPathname()) == old_path:
            _save(call, call.program)
        else:
            if existing is not None:
                if not overwrite:
                    raise FileExistsError(f"Project file exists: {existing.getPathname()}")
                existing.delete()
            target.createFile(program_name, call.program, call.monitor)
    new_path = str(call.program.getDomainFile().getPathname())
    call.context.programs.pop(old_path, None)
    call.context.programs[new_path] = call.info
    call.info.name = str(call.program.getName())
    call.runtime.invalidate(call.session)
    return {"saved": True, "path": new_path}


@operation("program.image_base.set", kind="write", api="Program.setImageBase")
def image_base_set(call, image_base, commit=True):
    call.program.setImageBase(address(call, image_base), commit)
    return {"image_base": str(call.program.getImageBase()), "commit": commit}


@operation(
    "program.export_binary", kind="project", api="GzfExporter, OriginalFileExporter, BinaryExporter"
)
def program_export_binary(call, path, format="original_file"):
    from ghidra.app.util.exporter import BinaryExporter, GzfExporter, OriginalFileExporter
    from java.io import File

    exporters = {
        "original_file": OriginalFileExporter,
        "original": OriginalFileExporter,
        "raw": BinaryExporter,
        "binary": BinaryExporter,
        "gzf": GzfExporter,
    }
    exporter_type = exporters.get(format.lower())
    if exporter_type is None:
        raise ValueError("format must be original_file, raw, or gzf; use project.export for GAR")
    call.runtime.guard(call.session, call.owner, no_pending=True)
    destination = Path(path).expanduser().resolve()
    exporter = exporter_type()
    if not exporter.export(File(str(destination)), call.program, None, call.monitor):
        raise RuntimeError(f"Ghidra export failed: {exporter.getMessageLog()}")
    return {"path": str(destination), "format": format, "size": destination.stat().st_size}


@operation("project.file.info", api="ProjectData.getFile")
def project_file_info(call, path):
    item = call.context.project.getProjectData().getFile(path)
    if item is None:
        raise ValueError(f"Project file not found: {path}")
    return _file_info(item)


@operation("project.files.list", api="DomainFolder.getFiles")
def project_files_list(
    call, folder_path="/", recursive=False, content_type=None, query=None, offset=0, limit=100
):
    items = (
        _file_info(item)
        for item in _files(_folder(call, folder_path), recursive)
        if (content_type is None or str(item.getContentType()) == content_type)
        and (query is None or query.casefold() in str(item.getPathname()).casefold())
    )
    return page(items, offset, limit, key="files")


@operation("project.folders.list", api="DomainFolder.getFolders")
def project_folders_list(call, folder_path="/", recursive=False):
    def walk(folder):
        for child in folder.getFolders():
            yield {"name": str(child.getName()), "path": str(child.getPathname())}
            if recursive:
                yield from walk(child)

    return {"folders": list(walk(_folder(call, folder_path)))}


@operation("project.search.programs", api="DomainFile.getContentType")
def project_search_programs(call, query=None, content_type=None, offset=0, limit=100):
    return project_files_list(call, "/", True, content_type or "Program", query, offset, limit)


@operation("project.program.open", kind="project", api="DomainFile.getDomainObject")
def project_program_open(call, path, read_only=None, update_analysis=False):
    context = call.context
    info = context._lookup_program_info(path)
    if info is None:
        item = context.project.getProjectData().getFile(path)
        if item is None or str(item.getContentType()) != "Program":
            raise ValueError(f"Project program not found: {path}")
        program = _open_program(call, context, path)
        info = context._init_program_info(program)
        context.programs[str(item.getPathname())] = info
    return _session(
        call,
        context,
        info,
        call.session.read_only if read_only is None else read_only,
        update_analysis,
    )


@operation(
    "project.program.open_existing",
    kind="project",
    api="GhidraProject.openProject, DomainFile.getDomainObject",
    program=False,
)
def project_program_open_existing(
    call,
    project_location,
    project_name,
    program_path=None,
    folder_path="/",
    program_name=None,
    read_only=True,
    update_analysis=False,
):
    context = call.runtime.registry.project_context(project_location, project_name, existing=True)
    call.runtime._attach_indexing(context)
    path = program_path or (
        str(PurePosixPath(folder_path) / program_name) if program_name else None
    )
    if path is None:
        files = list(_files(_root(context), True))
        programs = [item for item in files if str(item.getContentType()) == "Program"]
        if len(programs) != 1:
            raise ValueError(
                "Specify program_path or program_name "
                "when project does not contain exactly one program"
            )
        path = str(programs[0].getPathname())
    info = context._lookup_program_info(path)
    if info is None:
        program = _open_program(call, context, path)
        info = context._init_program_info(program)
        context.programs[str(program.getDomainFile().getPathname())] = info
    return _session(call, context, info, read_only, update_analysis)


@operation(
    "project.export", kind="project", api="DomainFile.copyTo, GhidraProject, GAR archive format"
)
def project_export(call, destination):
    """Archive a closed project snapshot, never an actively written DB directory."""
    from contextlib import ExitStack

    from ghidra.base.project import GhidraProject

    path = Path(destination).expanduser().resolve()
    if path.suffix.lower() == ".gzf":
        with call.runtime.program_lock(call.program):
            return program_export_binary(call, str(path), "gzf")
    if path.suffix.lower() != ".gar":
        raise ValueError("Project destination must end in .gar or .gzf")
    from .runtime import Session

    sessions = [
        Session(
            "project-export:" + call.owner,
            call.owner,
            call.session.project_id,
            call.context,
            info,
            False,
        )
        for info in list(call.context.programs.values())
    ]
    with ExitStack() as locks:
        for session in sorted(sessions, key=lambda item: id(item.info.program)):
            locks.enter_context(call.runtime.program_lock(session.info.program))
            call.runtime.guard(session, call.owner, no_pending=True)
        for session in sessions:
            _save(call, session.info.program)
        with tempfile.TemporaryDirectory(prefix="ghidra-mcp-archive-") as directory:
            name = str(call.context.project_name)
            snapshot = GhidraProject.createProject(directory, name, False)
            try:

                def copy_folder(source, target):
                    for item in source.getFiles():
                        item.copyTo(target, call.monitor)
                    for folder in source.getFolders():
                        copy_folder(folder, target.createFolder(str(folder.getName())))

                copy_folder(_root(call.context), snapshot.getRootFolder())
            finally:
                snapshot.close()
            root = Path(directory)
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.comment = f"Ghidra archive file for {name} project.".encode()
                archive.write(root / (name + ".gpr"), name + ".gpr")
                archive.writestr("JAR_FORMAT", "")
                project_dir = root / (name + ".rep")
                for item in project_dir.rglob("*"):
                    call.monitor.checkCancelled()
                    if (
                        item.is_file()
                        and not item.name.endswith(".ulock")
                        and item.parent != project_dir
                    ):
                        archive.write(item, str(item.relative_to(project_dir)))
    return {"destination": str(path), "format": "gar", "size": path.stat().st_size}


@operation("analysis.options.list", api="Options.getOptionNames/getObject")
def analysis_options_list(call, offset=0, limit=100, query=None):
    options = _options(call)
    return page(
        (
            {
                "name": str(name),
                "type": str(options.getType(name).name()),
                "value": _option_value(options, name),
            }
            for name in sorted(str(value) for value in options.getOptionNames())
            if query is None or query.casefold() in name.casefold()
        ),
        offset,
        limit,
        key="options",
    )


@operation("analysis.options.get", api="Options.getObject")
def analysis_options_get(call, name):
    options = _option(call, name)
    return {
        "name": name,
        "type": str(options.getType(name).name()),
        "value": _option_value(options, name),
    }


def _set_scalar_option(options, name, value, kind):
    scalar = _SCALAR_OPTIONS.get(kind)
    if scalar is None:
        return False
    suffix, _, convert = scalar
    if convert is bool:
        if not isinstance(value, bool):
            raise ValueError("Boolean analysis option requires a boolean")
    elif convert is int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("Integer analysis option requires an integer")
    elif isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Numeric analysis option requires a number")
    getattr(options, "set" + suffix)(name, convert(value))
    return True


def _set_enum_option(options, name, value):
    current = options.getObject(name, None)
    values = {
        str(item.name()): item for item in current.getDeclaringClass().getEnumConstants()
    }
    if not isinstance(value, str) or value not in values:
        raise ValueError(f"Enum analysis option requires one of: {list(values)}")
    options.setEnum(name, values[value])


def _set_file_option(options, name, value):
    from java.io import File

    if not isinstance(value, str):
        raise ValueError("File analysis option requires a path string")
    options.setFile(name, File(value))


def _set_date_option(options, name, value):
    from java.util import Date

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("Date analysis option requires milliseconds since the Unix epoch")
    options.setDate(name, Date(value))


def _set_bytes_option(options, name, value):
    import jpype

    if not isinstance(value, str):
        raise ValueError("Byte-array analysis option requires base64")
    options.setByteArray(name, jpype.JArray(jpype.JByte)(base64.b64decode(value, validate=True)))


_OBJECT_OPTION_SETTERS = {
    "ENUM_TYPE": _set_enum_option,
    "FILE_TYPE": _set_file_option,
    "DATE_TYPE": _set_date_option,
    "BYTE_ARRAY_TYPE": _set_bytes_option,
}


def _set_text_option(options, name, value, kind):
    if not isinstance(value, str):
        raise ValueError(f"Analysis option {kind} requires its Ghidra text representation")
    if kind == "STRING_TYPE":
        options.setString(name, value)
        return
    # Ghidra's typed codecs cover colors, fonts, shortcuts and custom values.
    converted = options.getType(name).convertStringToObject(value)
    if converted is None:
        raise ValueError(f"Invalid {kind} text representation")
    options.putObject(name, converted)


@operation("analysis.options.set", kind="write", api="Options typed setters")
def analysis_options_set(call, name, value):
    options = _option(call, name)
    kind = str(options.getType(name).name())
    if not _set_scalar_option(options, name, value, kind):
        setter = _OBJECT_OPTION_SETTERS.get(kind)
        if setter is None:
            _set_text_option(options, name, value, kind)
        else:
            setter(options, name, value)
    return analysis_options_get(call, name)


@operation("analysis.analyzers.list", api="Options analysis boolean entries")
def analysis_analyzers_list(call, offset=0, limit=100, query=None):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    manager = AutoAnalysisManager.getAnalysisManager(call.program)
    options = _options(call)
    return page(
        (
            {"name": name, "enabled": bool(options.getBoolean(name, False))}
            for name in sorted(str(value) for value in options.getOptionNames())
            if (query is None or query.casefold() in name.casefold())
            and str(options.getType(name).name()) == "BOOLEAN_TYPE"
            and manager.getAnalyzer(name) is not None
        ),
        offset,
        limit,
        key="analyzers",
    )


@operation("analysis.analyzers.set", kind="write", api="Options.setBoolean")
def analysis_analyzers_set(call, name, enabled):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    options = _option(call, name)
    if (
        AutoAnalysisManager.getAnalysisManager(call.program).getAnalyzer(name) is None
        or str(options.getType(name).name()) != "BOOLEAN_TYPE"
    ):
        raise ValueError(f"Not an analyzer enable option: {name}")
    return analysis_options_set(call, name, enabled)


@operation(
    "analysis.clear_cache",
    kind="project",
    api="DecompInterface.flushCache, Chroma.delete_collection",
)
def analysis_clear_cache(call):
    call.runtime.invalidate(call.session)
    return {"cleared": True}


@operation("analysis.status", api="AutoAnalysisManager.isAnalyzing")
def analysis_status(call):
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager

    return {
        "analysis_complete": call.info.analysis_complete,
        "running": bool(AutoAnalysisManager.getAnalysisManager(call.program).isAnalyzing()),
        "tasks": [
            call.runtime.task_status(task.task_id, call.owner)
            for task in list(call.runtime._tasks.values())
            if task.owner == call.owner and task.session.info.program is call.program
        ],
    }


@operation("analysis.update", kind="project", api="AutoAnalysisManager.startAnalysis")
def analysis_update(call):
    return call.runtime.submit_analysis(call.session, call.owner)


@operation("task.analysis_update", kind="project", api="AutoAnalysisManager.startAnalysis")
def task_analysis_update(call):
    return call.runtime.submit_analysis(call.session, call.owner)


@operation("analysis.update_and_wait", kind="write", api="AutoAnalysisManager.startAnalysis")
def analysis_update_and_wait(call):
    call.runtime.guard(call.session, call.owner, write=True, no_pending=True)
    return call.runtime.analyze(call.session, call.monitor)


@operation("task.status", api="Future state, TaskMonitor", program=False)
def task_status(call, task_id):
    return call.runtime.task_status(task_id, call.owner)


@operation("task.result", api="Future result", program=False)
def task_result(call, task_id):
    return call.runtime.task_result(task_id, call.owner)


@operation("task.cancel", kind="project", api="TaskMonitor.cancel", program=False)
def task_cancel(call, task_id):
    return call.runtime.cancel_task(task_id, call.owner)


@operation("transaction.begin", kind="project", api="Program.startTransaction")
def transaction_begin(call, description="MCP Transaction"):
    """Begin an owner-bound batch.

    Validation errors without program changes retain the batch. An operation
    that fails after modifying the program reverts the entire batch and reports
    that rollback in its error; Ghidra nested transactions are not savepoints.
    """
    return call.runtime.begin(call.session, call.owner, description)


@operation("transaction.commit", kind="project", api="Program.endTransaction")
def transaction_commit(call):
    return call.runtime.finish(call.session, call.owner, True)


@operation("transaction.revert", kind="project", api="Program.endTransaction")
def transaction_revert(call):
    return call.runtime.finish(call.session, call.owner, False)


@operation("transaction.status", api="Program.canUndo/canRedo")
def transaction_status(call):
    return call.runtime.transaction_status(call.session)


@operation("transaction.undo", kind="project", api="Program.undo")
def transaction_undo(call):
    call.runtime.guard(call.session, call.owner, write=True, no_pending=True)
    if not call.program.canUndo():
        raise ValueError("No transaction is available to undo")
    call.program.undo()
    call.runtime.invalidate(call.session)
    return transaction_status(call)


@operation("transaction.redo", kind="project", api="Program.redo")
def transaction_redo(call):
    call.runtime.guard(call.session, call.owner, write=True, no_pending=True)
    if not call.program.canRedo():
        raise ValueError("No transaction is available to redo")
    call.program.redo()
    call.runtime.invalidate(call.session)
    return transaction_status(call)
