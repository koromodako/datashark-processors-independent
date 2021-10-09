"""Datashark Yara Processor
"""
from typing import Dict
from platform import system
from asyncio.subprocess import PIPE
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument
from datashark_core.filesystem import prepend_workdir

NAME = 'yara'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class YaraProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Run yara on given filepath"""

    NAME = NAME
    SYSTEM = System.INDEPENDENT
    ARGUMENTS = [
        {
            'name': 'compiled_rules',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Load compiled rules",
        },
        {
            'name': 'count',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print only number of matches",
        },
        {
            'name': 'define',
            'kind': Kind.STR,
            'required': False,
            'description': "Define external variable",
        },
        {
            'name': 'fast_scan',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Fast matching mode",
        },
        {
            'name': 'identifier',
            'kind': Kind.STR,
            'required': False,
            'description': "Print only rules named identifier",
        },
        {
            'name': 'max_rules',
            'kind': Kind.INT,
            'required': False,
            'description': "Abort scanning after matching a number of rules",
        },
        {
            'name': 'negate',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print only not satisfied rules (negate)",
        },
        {
            'name': 'print_meta',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print metadata",
        },
        {
            'name': 'print_module',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print module data",
        },
        {
            'name': 'print_namespace',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print rules' namespace",
        },
        {
            'name': 'print_stats',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print rules' statistics",
        },
        {
            'name': 'print_strings',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print matching strings",
        },
        {
            'name': 'print_string_length',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print length of matched strings",
        },
        {
            'name': 'print_tags',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Print tags",
        },
        {
            'name': 'recursive',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Recursively search directories (follows symlinks)",
        },
        {
            'name': 'scan_list',
            'kind': Kind.BOOL,
            'value': 'false',
            'required': False,
            'description': "Scan files listed in file, one per line",
        },
        {
            'name': 'stack',
            'kind': Kind.INT,
            'required': False,
            'description': "Set maximum stack size (default=16384)",
        },
        {
            'name': 'tag',
            'kind': Kind.STR,
            'required': False,
            'description': "Print only rules tagged as tag",
        },
        {
            'name': 'threads',
            'kind': Kind.INT,
            'required': False,
            'description': "Use the specified number of threads to scan a directory",
        },
        {
            'name': 'timeout',
            'kind': Kind.INT,
            'required': False,
            'description': "Abort scanning after the given number of seconds",
        },
        {
            'name': 'rules',
            'kind': Kind.PATH,
            'required': True,
            'description': "Path to yara rule file",
        },
        {
            'name': 'filepath',
            'kind': Kind.PATH,
            'required': True,
            'description': "Path to file or directory to scan",
        },
        {
            'name': 'output',
            'kind': Kind.PATH,
            'required': True,
            'description': "Path to report file to produce",
        },
    ]
    DESCRIPTION = """
    Run yara on given filepath (yara is a cross-platform tool)
    """

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process a file using yara"""
        output = arguments.get('output').get_value()
        output = prepend_workdir(self.config, output)
        # invoke subprocess
        try:
            system_name = System(system())
        except ValueError as exc:
            raise ProcessorError("current system is not a valid system") from exc
        proc = await self._start_subprocess(
            f'datashark.processors.yara.bin.{system_name.value.lower()}',
            [],
            [
                # optional
                ('compiled_rules', '-C'),
                ('count', '-c'),
                ('define', '-d'),
                ('fast_scan', '-f'),
                ('identifier', '-i'),
                ('max_rules', '-l'),
                ('negate', '-n'),
                ('print_meta', '-m'),
                ('print_module-data', '-D'),
                ('print_namespace', '-e'),
                ('print_stats', '-S'),
                ('print_strings', '-s'),
                ('print_string_length', '-L'),
                ('print_tags', '-g'),
                ('recursive', '-r'),
                ('scan_list', '--scan-list'),
                ('stack-size', '-k'),
                ('tag', '-t'),
                ('threads', '-p'),
                ('timeout', '-a'),
                # positional
                ('rules', None),
                ('filepath', None),
            ],
            arguments,
            stdout=PIPE,
            stderr=PIPE,
        )
        # WARN: current implementation does not manage memory consumption
        #       out-of-memory exceptions can occur if subprocess produces to
        #       much data on either stdout or stderr.
        stdout, _ = await self._handle_communicating_process(proc)
        output.write_bytes(stdout)
