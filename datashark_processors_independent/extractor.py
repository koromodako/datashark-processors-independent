"""Datashark Template Plugin
"""
from typing import Dict
from pathlib import Path
from zipfile import ZipFile
from tarfile import TarFile
from datashark_core.meta import ProcessorMeta
from datashark_core.logging import LOGGING_MANAGER
from datashark_core.processor import ProcessorInterface, ProcessorError
from datashark_core.model.api import Kind, System, ProcessorArgument
from datashark_core.filesystem import prepend_workdir


NAME = 'extractor'
LOGGER = LOGGING_MANAGER.get_logger(NAME)


def __check_path_traversal(name):
    """Check path traversal indicators"""
    member_path = Path(name)
    if member_path.is_absolute():
        LOGGER.warning("absolute path traversal attempt: %s", name)
        return True
    if '..' in member_path.parts:
        LOGGER.warning("relative path traversal attempt: %s", name)
        return True
    return False


class ExtractorProcessor(ProcessorInterface, metaclass=ProcessorMeta):
    """Extractor processor"""

    NAME = NAME
    SYSTEM = System.INDEPENDENT
    ARGUMENTS = [
        {
            'name': 'password',
            'kind': Kind.STR,
            'required': False,
            'description': "Optional password for zip archives",
        },
        {
            'name': 'archive_path',
            'kind': Kind.PATH,
            'required': True,
            'description': "Archive to extract",
        },
        {
            'name': 'output_dir',
            'kind': Kind.PATH,
            'required': True,
            'description': "Output directory",
        },
    ]
    DESCRIPTION = """
    Extractor processor, extract zip & tar archives
    """

    async def __process_zip(self, archive_path, output_dir, password):
        """Process zip archive"""
        with ZipFile(archive_path) as ziparchive:
            if password:
                ziparchive.setpassword(password)
            for name in ziparchive.namelist():
                if __check_path_traversal(name):
                    continue
                ziparchive.extract(name, output_dir)

    async def __process_tar(self, archive_path, output_dir):
        """Process tar archive"""
        with TarFile(archive_path) as tararchive:
            for name in tararchive.getnames():
                if __check_path_traversal(name):
                    continue
                tararchive.extract(name, output_dir)

    async def _run(self, arguments: Dict[str, ProcessorArgument]):
        """Process a file using hashers"""
        password = arguments.get('password').get_value()
        if password:
            password = password.encode()
        # load and check filepath argument
        archive_path = prepend_workdir(
            self.config, arguments.get('archive_path').get_value()
        )
        if not archive_path.is_file():
            raise ProcessorError(f"archive {archive_path} not found!")
        # load output file argument
        output_dir = prepend_workdir(
            self.config, arguments.get('output_dir').get_value()
        )
        # create output directory if needed
        output_dir.mkdir(parents=True, exist_ok=True)
        # determine if is zip archive
        if archive_path.suffix == '.zip':
            self.__process_zip(archive_path, output_dir, password)
        else:
            self.__process_tar(archive_path, output_dir)
