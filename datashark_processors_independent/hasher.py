"""Datashark Template Plugin
"""
from typing import Dict
from pathlib import Path
from hashlib import new as new_md, algorithms_guaranteed
from textwrap import indent
from aiofiles import open as async_open
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import (
    INDENT_UNIT,
    Kind,
    System,
    ProcessorArgument,
)
from datashark_core.filesystem import prepend_workdir


NAME = 'hasher'
LOGGER = LOGGING_MANAGER.get_logger(NAME)
ALGORITHMS = '\n' + indent(
    '\n'.join(sorted(algorithms_guaranteed)), ' ' * 16 + INDENT_UNIT
)


class HasherProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Hasher processor"""

    NAME = NAME
    SYSTEM = System.INDEPENDENT
    ARGUMENTS = [
        {
            'name': 'hashers',
            'kind': Kind.STR,
            'value': 'md5,sha1',
            'required': False,
            'description': f"""
                Comma separated list of hashers among{ALGORITHMS}
            """,
        },
        {
            'name': 'filepath',
            'kind': Kind.PATH,
            'required': True,
            'description': """
                File to hash or directory to explore to find files to hash
            """,
        },
        {
            'name': 'output_file',
            'kind': Kind.PATH,
            'required': True,
            'description': "Output filename",
        },
    ]
    DESCRIPTION = """
    Hasher processor, compute file hashes
    """

    async def __process_file(self, hashers, filepath):
        """process a single file"""
        md_dct = {hasher: new_md(hasher) for hasher in sorted(hashers)}
        async with async_open(str(filepath), 'rb') as aiofstream_in:
            while True:
                chunk = await aiofstream_in.read(1024 * 1024)
                if not chunk:
                    break
                for md_ in md_dct.values():
                    md_.update(chunk)
        return [md_dct[hasher].hexdigest() for hasher in sorted(hashers)]

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process a file using hashers"""
        # load and check hashers argument
        hashers = list(
            set(arguments.get('hashers').get_value().split(',')).intersection(
                algorithms_guaranteed
            )
        )
        if not hashers:
            raise ProcessorError("failed to find a valid hasher!")
        # load and check filepath argument
        filepath = prepend_workdir(
            self.config, arguments.get('filepath').get_value()
        )
        if not filepath.is_file() and not filepath.is_dir():
            raise ProcessorError(f"filepath {filepath} not found!")
        # load output file argument
        output_file = prepend_workdir(
            self.config, arguments.get('output_file').get_value()
        )
        # create output file
        output_file.parent.mkdir(parents=True, exist_ok=True)
        async with async_open(str(output_file), 'w') as aiofstream_out:
            # write output file header
            headers = ','.join(list(sorted(hashers)) + ['filepath'])
            await aiofstream_out.write(f"{headers}\n")
            # determine if file or dict
            files = [filepath]
            is_dir = False
            if filepath.is_dir():
                files = filepath.rglob('*')
                is_dir = True
            # iterate over file(s)
            for file in files:
                # ensure file is a regular file
                if not file.is_file():
                    continue
                # compute file relative path or name
                fpath = file.relative_to(filepath) if is_dir else file.name
                # compute file digests
                hexdigests = ','.join(await self.__process_file(hashers, file))
                # write line to output file
                await aiofstream_out.write(f'{hexdigests},"{fpath}"\n')
