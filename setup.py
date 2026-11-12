from setuptools import setup, find_packages


# Taken from option 3 of https://packaging.python.org/guides/single-sourcing-package-version/
version = {}
with open('waterbutler/version.py') as fp:
    exec(fp.read(), version)

setup(
    name='waterbutler',
    version=version['__version__'],
    description='WaterButler Storage Server',
    author='Center for Open Science',
    author_email='contact@cos.io',
    url='https://github.com/CenterForOpenScience/waterbutler',
    packages=find_packages(exclude=("tests*", )),
    package_dir={'waterbutler': 'waterbutler'},
    include_package_data=True,
    zip_safe=False,
    license='Apache-2.0',
    classifiers=[
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.13',
        'Development Status :: 5 - Production/Stable',
    ],
    provides=[
        'waterbutler.auth',
        'waterbutler.providers',
    ],
    entry_points={
        'waterbutler.auth': [
            'osf = waterbutler.auth.osf:OsfAuthHandler',
        ],
        'waterbutler.providers': [
            'cloudfiles = waterbutler.providers.cloudfiles:CloudFilesProvider',
            'dropbox = waterbutler.providers.dropbox:DropboxProvider',
            'figshare = waterbutler.providers.figshare:FigshareProvider',
            'filesystem = waterbutler.providers.filesystem:FileSystemProvider',
            'github = waterbutler.providers.github:GitHubProvider',
            'gitlab = waterbutler.providers.gitlab:GitLabProvider',
            'bitbucket = waterbutler.providers.bitbucket:BitbucketProvider',
            'osfstorage = waterbutler.providers.osfstorage:OSFStorageProvider',
            'owncloud = waterbutler.providers.owncloud:OwnCloudProvider',
            's3 = waterbutler.providers.s3:S3Provider',
            'dataverse = waterbutler.providers.dataverse:DataverseProvider',
            'box = waterbutler.providers.box:BoxProvider',
            'googledrive = waterbutler.providers.googledrive:GoogleDriveProvider',
            'onedrive = waterbutler.providers.onedrive:OneDriveProvider',
            'googlecloud = waterbutler.providers.googlecloud:GoogleCloudProvider',
            'swift = waterbutler.providers.swift:SwiftProvider',
            'azureblobstorage = waterbutler.providers.azureblobstorage:AzureBlobStorageProvider',
            'weko = waterbutler.providers.weko:WEKOProvider',
            's3compat = waterbutler.providers.s3compat:S3CompatProvider',
            's3compatsigv4 = waterbutler.providers.s3compatsigv4:S3CompatSigV4Provider',
            's3compatb3 = waterbutler.providers.s3compatb3:S3CompatB3Provider',
            'nextcloud = waterbutler.providers.nextcloud:NextcloudProvider',
            'iqbrims = waterbutler.providers.iqbrims:IQBRIMSProvider',
            'dropboxbusiness = waterbutler.providers.dropboxbusiness:DropboxBusinessProvider',
            'nextcloudinstitutions = waterbutler.providers.nextcloudinstitutions:NextcloudInstitutionsProvider',
            's3compatinstitutions = waterbutler.providers.s3compatinstitutions:S3CompatInstitutionsProvider',
            'ociinstitutions = waterbutler.providers.ociinstitutions:OCIInstitutionsProvider',
            'onedrivebusiness = waterbutler.providers.onedrivebusiness:OneDriveBusinessProvider',
            'rushfiles = waterbutler.providers.rushfiles:RushFilesProvider',
        ],
    },
)
