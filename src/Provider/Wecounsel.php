<?php

namespace Stevenmaguire\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\ArrayAccessorTrait;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;

class Wecounsel extends AbstractProvider
{
    use ArrayAccessorTrait,
        BearerAuthorizationTrait;

    /**
     * Wecounsel environment specific host; defaults to api
     *
     * @var string
     */
    protected $host = 'https://api.wecounsel.com';

    /**
     * Returns an authenticated PSR-7 request instance.
     *
     * @param  string $method
     * @param  string $url
     * @param  AccessToken|string $token
     * @param  array $options Any of "headers", "body", and "protocolVersion".
     * @return \Psr\Http\Message\RequestInterface
     */
    public function getAuthenticatedRequest($method, $url, $token, array $options = [])
    {
        $options['headers']['content-type'] = 'application/vnd.api+json';

        return $this->createRequest($method, $url, $token, $options);
    }

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->getHost() . '/oauth/authorize';
    }

    /**
     * Get access token url to retrieve token
     *
     * @return string
s     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->getHost() . '/oauth/token';
    }

    /**
     * Get provider url to fetch user details
     *
     * @param  AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->getHost() . '/v1/users/me';
    }

    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [];
    }

    /**
     * Returns a cleaned host.
     *
     * @return string
     */
    public function getHost()
    {
        return rtrim($this->host, '/');
    }

    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator, defaults to ' '
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }

    /**
     * Check a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        // At the time of initial implementation the possible error payloads returned
        // by WeCounsel were not very well documented. This method will need some
        // improvement as the API continues to mature.
        if ($response->getStatusCode() != 200) {
            throw new IdentityProviderException('Unexpected response code', $response->getStatusCode(), $response);
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param object $response
     * @param AccessToken $token
     * @return WecounselResourceOwner
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new WecounselResourceOwner($response);
    }
}
