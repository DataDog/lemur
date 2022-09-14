# GCP Plugin

## Destination
The destination plugin allows certificates to be uploaded to a given GCP account.
Currently there are 2 ways to authenticate against GCP. Via vault using [Google Cloud 
Secrets engine](https://www.vaultproject.io/docs/secrets/gcp) or by using [service account credentials](https://cloud.google.com/iam/docs/service-accounts).

#### Authentication by Vault
When setting up the new destination in the lemur console set the "using vault" value to True. 
Then enter the path to your secret credentials. Lemur will use this token to authenticate API requests.

#### Authentication by Service Account Credentials
In the GCP console generate a new set of Service Account Credentials. Store those on your server and then
set the `PATH_TO_GOOGLE_APPLICATION_CREDENTIALS` env variable in the lemur.conf file to point to where that key is stored.
ex:
```commandline
PATH_TO_GOOGLE_APPLICATION_CREDENTIALS = '/tmp/authentication.json'
```