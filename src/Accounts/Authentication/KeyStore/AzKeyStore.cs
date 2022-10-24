// ----------------------------------------------------------------------------------
//
// Copyright Microsoft Corporation
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------------

using Microsoft.Azure.Commands.Common.Authentication.Abstractions.Core;
using Microsoft.Azure.Commands.Common.Authentication.Abstractions;
using Microsoft.Identity.Client.Extensions.Msal;
using Microsoft.WindowsAzure.Commands.Common;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Text;

namespace Microsoft.Azure.Commands.ResourceManager.Common
{
    public class AzKeyStore : IDisposable
    {
        public const string Name = "AzKeyStore";

        internal class KeyStoreElement
        {
            public string keyStoreKey;
            public string keyType;
            public string secret;
        }

        private static IDictionary<IKeyStoreKey, SecureString> _credentials = new Dictionary<IKeyStoreKey, SecureString>();
        Storage _storage = null;
        bool autoSave = true;
        Exception lastError = null;

        //fixme: remove linux tag or set as plaintext
        public const string KeyChainServiceName = "Microsoft.Azure.PowerShell";
        public const string LinuxKeyRingSchema = "Microsoft.Azure.PowerShell";
        public const string LinuxKeyRingCollection = MsalCacheHelper.LinuxKeyRingDefaultCollection;
        public static readonly KeyValuePair<string, string> LinuxKeyRingAttr1 = new KeyValuePair<string, string>("MsalClientID", "Microsoft.Azure.PowerShell");
        public static readonly KeyValuePair<string, string> LinuxKeyRingAttr2 = new KeyValuePair<string, string>("Microsoft.Azure.PowerShell", "1.0.0.0");

        public AzKeyStore()
        {

        }

        [Obsolete("The constructor is deprecated. Will read key from encryted storage later.", false)]
        public AzKeyStore(IAzureContextContainer profile)
        {
            if (profile != null && profile.Accounts != null)
            {
                foreach (var account in profile.Accounts)
                {
                    if (account != null && account.ExtendedProperties.ContainsKey(AzureAccount.Property.ServicePrincipalSecret))
                    {
                        IKeyStoreKey keyStoreKey = new ServicePrincipalKey(AzureAccount.Property.ServicePrincipalSecret, account.Id
                            , account.GetTenants().FirstOrDefault());
                        var servicePrincipalSecret = account.ExtendedProperties[AzureAccount.Property.ServicePrincipalSecret];
                        _credentials[keyStoreKey] = servicePrincipalSecret.ConvertToSecureString();
                    }
                }
            }
        }

        public AzKeyStore(string directory, string fileName, bool loadStorage = true, bool autoSaveEnabled = true)
        {
            autoSave = autoSaveEnabled;
            StorageCreationPropertiesBuilder storageProperties = null;
            try
            {
                storageProperties = new StorageCreationPropertiesBuilder(fileName, directory)
                    .WithMacKeyChain(KeyChainServiceName + ".other_secrets", fileName)
                    .WithLinuxUnprotectedFile();
                _storage = Storage.Create(storageProperties.Build());
                _storage.VerifyPersistence();
            }
            catch (MsalCachePersistenceException e)
            {
                _storage.Clear();
                storageProperties = new StorageCreationPropertiesBuilder(fileName, directory).WithUnprotectedFile();
                _storage = Storage.Create(storageProperties.Build());
                lastError = e;
            }
            if (loadStorage)
            {
                LoadStorage();
            }
        }

        public void LoadStorage()
        {
            _storage.VerifyPersistence();
            var data = _storage.ReadData();
            if (data != null && data.Length > 0)
            {
                var rawJsonString = Encoding.UTF8.GetString(data);
                var serializableKeyStore = JsonConvert.DeserializeObject(rawJsonString, typeof(List<KeyStoreElement>)) as List<KeyStoreElement>;
                if (serializableKeyStore != null)
                {
                    foreach (var item in serializableKeyStore)
                    {
                        Type type = Type.GetType(item.keyType);
                        IKeyStoreKey keyStoreKey = JsonConvert.DeserializeObject(item.keyStoreKey, type) as IKeyStoreKey;
                        if (keyStoreKey != null)
                        {
                            _credentials[keyStoreKey] = item.secret.ConvertToSecureString();
                        }
                    }
                }
            }
        }

        public void ClearCache()
        {
            _credentials.Clear();
        }

        public void Flush()
        {
            IList<KeyStoreElement> serializableKeyStore = new List<KeyStoreElement>();
            foreach (var item in _credentials)
            {
                string key = JsonConvert.SerializeObject(item.Key);
                if (!string.IsNullOrEmpty(key))
                {
                    serializableKeyStore.Add(new KeyStoreElement()
                    {
                        keyStoreKey = key,
                        keyType = item.Key.GetType().FullName,
                        secret = item.Value.ConvertToString()
                    });
                }
            }

            if (serializableKeyStore.Count > 0)
            {
                var JsonString = JsonConvert.SerializeObject(serializableKeyStore);
                _storage.WriteData(Encoding.UTF8.GetBytes(JsonString));
            }
        }

        public void Dispose()
        {
            if (autoSave)
            {
                Flush();
            }
            ClearCache();
        }

        public void SaveKey(IKeyStoreKey key, SecureString value)
        {
            _credentials[key] = value;
        }

        public SecureString GetKey(IKeyStoreKey key)
        {
            if (_credentials.ContainsKey(key))
            {
                return _credentials[key];
            }
            return null;
        }

        public bool DeleteKey(IKeyStoreKey key)
        {
            return _credentials.Remove(key);
        }

        public void EnableAutoSaving()
        {
            autoSave = true;
        }

        public void DisableAutoSaving()
        {
            autoSave = false;
        }

        public Exception GetLastError()
        {
            return lastError;
        }
    }
}
