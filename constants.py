"""Module containing constants and static configurations for the email analysis system."""

DANGEROUS_CONTENT_TYPES = {
    '.exe': [
        'application/x-msdownload',
        'application/x-msdos-program',
        'application/exe',
        'application/x-exe',
        'application/octet-stream',
    ],
    '.bat': [
        'application/bat',
        'application/x-bat',
        'text/x-bat',
    ],
    '.vbs': [
        'application/x-vbs',
        'text/vbscript',
        'application/vnd.ms-vbscript',
    ],
    '.js': [
        'application/javascript',
        'application/x-javascript',
        'text/javascript',
    ],
    '.scr': [
        'application/x-screensaver',
        'application/octet-stream',
    ],
    '.iso': [
        'application/x-iso9660-image',
    ],
    '.cab': [
        'application/vnd.ms-cab-compressed',
    ],
}