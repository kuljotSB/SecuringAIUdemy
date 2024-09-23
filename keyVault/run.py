from dotenv import load_dotenv
import os
from azure.core.credentials import AzureKeyCredential
from azure.keyvault.secrets import SecretClient
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

from openai import AzureOpenAI


def main():
    global cog_endpoint
    global cog_key

   
    # Get Configuration Settings
    openai_endpoint = 'YOUR_OPENAI_ENDPOINT'
    key_vault_name = 'THE_KEY_VAULT_NAME'
    client_id = "YOUR_CLIENT_ID"
    secret_name = "YOUR_SECRET_NAME"
    model = "YOUR_GPT_ENGINE_NAME"

    # Get Azure AI services key from keyvault using the service principal credentials
    key_vault_uri = f"https://{key_vault_name}.vault.azure.net/"
    credential = DefaultAzureCredential(managed_identity_client_id=client_id)
    keyvault_client = SecretClient(key_vault_uri, credential)
    secret_key = keyvault_client.get_secret(secret_name)
    openai_key = secret_key.value
    print("openai primary key is: {}".format(openai_key))

    client = AzureOpenAI(
      azure_endpoint = openai_endpoint,
      api_key = openai_key,
      api_version = "2024-02-15-preview"
    )

    user_query = input("enter your query for the gpt engine" + "\n")

    response = client.chat.completions.create(
      model = model,
      messages = [
        {
          "role":"system", "content":"you are a helpful AI assistant"
        },
        {
          "role":"user", "content": user_query
        }
      ]
    )

    print("the information is:" + response.choices[0].message.content + "\n")
  
    
    
        




if __name__ == "__main__":
    main()
