"""Real-runtime acceptance cases for the opt-in script bridge."""

import os
from pathlib import Path

from pyghidra_mcp.advanced import trusted


def smoke_trusted(runtime, owner, session_id, scratch):
    directory = Path(scratch["directory"])
    directory.mkdir(parents=True, exist_ok=True)
    previous = os.environ.get("GHIDRA_ADVANCED_TRUSTED_CODE")
    os.environ["GHIDRA_ADVANCED_TRUSTED_CODE"] = "1"
    results = {}

    def invoke(handler, **arguments):
        return runtime.invoke(handler.__operation__, {"session_id": session_id, **arguments}, owner)

    try:
        application = runtime.invoke(trusted.info.__operation__, {}, owner)
        assert application["ghidra_version"] == "12.1.4", application
        results["ghidra.info"] = application
        result = invoke(trusted.call_api, target="program.getName")
        assert result["result"], result
        results["ghidra.call"] = result
        result = invoke(trusted.evaluate, code="values = [19, 23]\nsum(values)")
        assert result["result"] == 42, result
        results["ghidra.eval"] = result
        python_script = directory / "advanced_script.py"
        python_script.write_text("println(getScriptArgs()[0])\nresult = 6 * 7\n", encoding="utf-8")
        result = invoke(trusted.script, path=str(python_script), script_args=["advanced-python"])
        assert result["result"] == 42 and result["stdout"].strip() == "advanced-python", result
        java_script = directory / "AdvancedCatalogSmoke.java"
        java_script.write_text(
            "import ghidra.app.script.GhidraScript;\n"
            "public class AdvancedCatalogSmoke extends GhidraScript {\n"
            "    public void run() throws Exception {\n"
            '        println("advanced-java-" + currentProgram.getName());\n'
            "    }\n"
            "}\n",
            encoding="utf-8",
        )
        java_result = invoke(trusted.script, path=str(java_script), script_args=[])
        assert "advanced-java-" in java_result["stdout"], java_result
        results["ghidra.script"] = {"python": result, "java": java_result}
        return results
    finally:
        if previous is None:
            os.environ.pop("GHIDRA_ADVANCED_TRUSTED_CODE", None)
        else:
            os.environ["GHIDRA_ADVANCED_TRUSTED_CODE"] = previous
