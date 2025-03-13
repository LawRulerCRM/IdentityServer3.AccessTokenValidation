/*
 * Copyright 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Jwt;
using System;
using System.Collections.Generic;
//using System.IdentityModel.Tokens;
using System.Net.Http;
using System.Security.Cryptography;
using System.Threading;

namespace IdentityServer3.AccessTokenValidation
{
    internal class DiscoveryDocumentIssuerSecurityTokenProvider : IIssuerSecurityKeyProvider
    {
        private readonly ReaderWriterLockSlim _synclock = new ReaderWriterLockSlim();
        private readonly ConfigurationManager<OpenIdConnectConfiguration> _configurationManager;
        private readonly ILogger _logger;
        private string _issuer;
        //private IEnumerable<SecurityToken> _tokens;
        private IEnumerable<SecurityKey> _keys;

        public DiscoveryDocumentIssuerSecurityTokenProvider(string discoveryEndpoint, IdentityServerBearerTokenAuthenticationOptions options, ILoggerFactory loggerFactory)
        {
            _logger = loggerFactory.Create(this.GetType().FullName);

            var handler = options.BackchannelHttpHandler ?? new WebRequestHandler();

            if (options.BackchannelCertificateValidator != null)
            {
                // Set the cert validate callback
                var webRequestHandler = handler as WebRequestHandler;
                if (webRequestHandler == null)
                {
                    throw new InvalidOperationException("The back channel handler must derive from WebRequestHandler in order to use a certificate validator");
                }
                webRequestHandler.ServerCertificateValidationCallback = options.BackchannelCertificateValidator.Validate;
            }

            _configurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(discoveryEndpoint, new OpenIdConnectConfigurationRetriever(), new HttpClient(handler))
            {
                AutomaticRefreshInterval = options.AutomaticRefreshInterval
            };

            if (!options.DelayLoadMetadata)
            {
                RetrieveMetadata();
            }
        }

        /// <summary>
        /// Gets the issuer the credentials are for.
        /// </summary>
        /// <value>
        /// The issuer the credentials are for.
        /// </value>
        public string Issuer
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _issuer;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /// <value>
        /// The identity server default audience
        /// </value>
        public string Audience
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    var issuer = _issuer.EnsureTrailingSlash();
                    return issuer + "resources";
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        /*
        /// <summary>
        /// Gets all known security tokens.
        /// </summary>
        /// <value>
        /// All known security tokens.
        /// </value>
        public IEnumerable<SecurityToken> SecurityTokens
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _tokens;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }
        */

        /// <summary>
        /// Gets all known security keys.
        /// </summary>
        /// <value>
        /// All known security keys.
        /// </value>
        public IEnumerable<SecurityKey> SecurityKeys
        {
            get
            {
                RetrieveMetadata();
                _synclock.EnterReadLock();
                try
                {
                    return _keys;
                }
                finally
                {
                    _synclock.ExitReadLock();
                }
            }
        }

        private void RetrieveMetadata()
        {
            _synclock.EnterWriteLock();
            try
            {
                var result = AsyncHelper.RunSync(async () => await _configurationManager.GetConfigurationAsync());

                if (result.JsonWebKeySet == null)
                {
                    _logger.WriteError("Discovery document has no configured signing key. aborting.");
                    throw new InvalidOperationException("Discovery document has no configured signing key. aborting.");
                }

                /*var keys = new List<SecurityKey>();
                foreach (var key in result.JsonWebKeySet.Keys)
                {
                    var rsa = RSA.Create();
                    rsa.ImportParameters(new RSAParameters
                    {
                        Exponent = Base64UrlEncoder.DecodeBytes(key.E),
                        Modulus = Base64UrlEncoder.DecodeBytes(key.N)
                    });

                    foreach (System.IdentityModel.Tokens.SecurityKey sKey in new System.IdentityModel.Tokens.RsaSecurityToken(rsa, key.Kid).SecurityKeys)
                    {
                        keys.Add((SecurityKey)sKey);
                    }
                }
                */

                _issuer = result.Issuer;
                _keys = result.JsonWebKeySet.Keys;
            }
            catch (Exception ex)
            {
                _logger.WriteError("Error contacting discovery endpoint: " + ex.ToString());
                throw;
            }
            finally
            {
                _synclock.ExitWriteLock();
            }
        }
    }
}