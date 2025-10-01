import { IDPConfig } from './types';
import { parseDom } from './xml';
import { NS } from './const';

export const getIdentityProviders = (
  xml: string,
  httpPost: boolean,
): IDPConfig[] => {
  const dom = parseDom(xml);
  const idps = Array.from(
    dom.getElementsByTagNameNS(NS.SAML_METADATA, 'EntityDescriptor'),
  );
  const binding =
    'urn:oasis:names:tc:SAML:2.0:bindings:' +
    (httpPost ? 'HTTP-POST' : 'HTTP-Redirect');

  return idps.map((idp) => {
    const getLocation = (tag: string) =>
      Array.from(idp.getElementsByTagNameNS(NS.SAML_METADATA, tag))
        .find((x) => x.getAttribute('Binding') === binding)
        ?.getAttribute('Location');

    // ✅ Trova prima il certificato "signing", altrimenti fallback al primo trovato
    const signingCert = (() => {
      const idpSSO = idp.getElementsByTagNameNS(
        NS.SAML_METADATA,
        'IDPSSODescriptor',
      ).item(0);

      if (idpSSO) {
        const keyDescriptors = Array.from(
          idpSSO.getElementsByTagNameNS(NS.SAML_METADATA, 'KeyDescriptor'),
        );

        const signingKey = keyDescriptors.find(
          (kd) => kd.getAttribute('use') === 'signing',
        );

        if (signingKey) {
          const cert = signingKey
            .getElementsByTagNameNS(NS.SIG, 'X509Certificate')
            .item(0)?.textContent;
          if (cert) return cert;
        }
      }

      // 🔄 Fallback: prendi il primo certificato disponibile (vecchio comportamento)
      return (
        idp.getElementsByTagNameNS(NS.SIG, 'X509Certificate').item(0)
          ?.textContent || null
      );
    })();

    return {
      entityId: idp.getAttribute('entityID'),
      cert: signingCert,
      entryPoint: getLocation('SingleSignOnService'),
      logoutUrl: getLocation('SingleLogoutService'),
    };
  });
};
