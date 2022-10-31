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

using Microsoft.Identity.Client.Extensions.Msal;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Concurrent;
using System.Text;

namespace Microsoft.Azure.Commands.ResourceManager.Common
{
    public class AzKeyStore : IDisposable
    {
        public const string Name = "AzKeyStore";

        internal class KeyStoreElement
        {
            public string keyType;
            public string keyStoreKey;
            public string valueType;
            public string keyStoreValue;
        }

        private static IDictionary<Type, string> _typeNameMap = new ConcurrentDictionary<Type, string>();
        private static IDictionary<string, JsonConverter> _elementConverterMap = new ConcurrentDictionary<string, JsonConverter>();

        public static void RegisterJsonConverter(Type type, JsonConverter converter)
        {
            _typeNameMap[type] = type.FullName.Split('.').LastOrDefault();
            _elementConverterMap[_typeNameMap[type]] = converter;
        }

        private IDictionary<IKeyStoreKey, Object> _credentials = new ConcurrentDictionary<IKeyStoreKey, Object>();
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
                        if (_elementConverterMap.ContainsKey(item.keyType))
                        {
                            IKeyStoreKey keyStoreKey = JsonConvert.DeserializeObject<Object>(item.keyStoreKey, _elementConverterMap[item.keyType]) as IKeyStoreKey ;
                            if (keyStoreKey != null && _elementConverterMap.ContainsKey(item.valueType))
                            {
                                _credentials[keyStoreKey] = JsonConvert.DeserializeObject<object>(item.keyStoreValue, _elementConverterMap[item.valueType]);
                            }
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
                var keyType = _typeNameMap[item.Key.GetType()];
                var key = JsonConvert.SerializeObject(item.Key, _elementConverterMap[keyType]);
                if (!string.IsNullOrEmpty(key))
                {
                    var valueType = _typeNameMap[item.Value.GetType()];
                    serializableKeyStore.Add(new KeyStoreElement()
                    {
                        keyStoreKey = key,
                        keyType = keyType,
                        keyStoreValue = JsonConvert.SerializeObject(item.Value, _elementConverterMap[valueType]),
                        valueType = valueType
                    }) ;
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

        public void SaveKey<T>(IKeyStoreKey key, T value) where T : class
        {
            if (!_typeNameMap.ContainsKey(key.GetType()) || !_typeNameMap.ContainsKey(value.GetType()))
            {
                throw new InvalidOperationException("Please register key & values type before save it.");
            }
            _credentials[key] = value;
        }

        public T GetKey<T>(IKeyStoreKey key) where T : class
        {
            if (_credentials.ContainsKey(key))
            {
                return _credentials[key] as T;
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
