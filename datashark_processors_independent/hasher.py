"""Datashark Template Plugin
"""
from typing import List
from hashlib import new as new_md, algorithms_guaranteed
from aiofile import async_open
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument
from datashark_core.filesystem import prepend_workdir


NAME = 'hasher'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


class HasherProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Hasher of a processor"""

    NAME = NAME
    SYSTEM = System.INDEPENDENT
    ARGUMENTS = [
        {
            'name': 'hashers',
            'kind': Kind.STR,
            'value': 'md5,sha1',
            'required': False,
            'description': f"""
                Comma separated list of hashers among {algorithms_guaranteed}
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
            async for chunk in aiofstream_in.iter_chunked(1024*1024):
                for md_ in md_dct.values():
                    md_.update(chunk)
        return [md_dct[hasher].hexdigest() for hasher in sorted(hashers)]

    async def _run(self, arguments: List[ProcessorArgument]):
        """Process a file using hashers"""
        # retrieve workdir and check access to it
        workdir = self.config.get('datashark.agent.workdir')
        if not workdir.is_dir():
            raise ProcessorError("agent-side workdir not found!")
        # retrieve arguments
        hashers = None
        filepath = None
        output_file = None
        for proc_arg in arguments:
            if proc_arg.name == 'hashers':
                hashers = list(
                    set(proc_arg.get_value().split(',')).intersection(algorithms_guaranteed)
                )
                if not hashers:
                    raise ProcessorError("failed to find a valid hasher!")
                continue
            if proc_arg.name == 'filepath':
                filepath = prepend_workdir(workdir, proc_arg.get_value())
                if not filepath.is_file() and not filepath.is_dir():
                    raise ProcessorError(f"filepath {filepath} not found!")
                continue
            if proc_arg.name == 'output_file':
                output_file = prepend_workdir(workdir, proc_arg.get_value())
                continue
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
                fpath = file.relative_to(filepath) if is_dir else file.stem
                # compute file digests
                hexdigests = ','.join(self.__process_file(hashers, file))
                # write line to output file
                await aiofstream_out.write(f"{hexdigests},{fpath}\n")
