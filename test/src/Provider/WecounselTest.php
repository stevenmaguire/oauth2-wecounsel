<?php

namespace Stevenmaguire\OAuth2\Client\Test\Provider;

use League\OAuth2\Client\Tool\QueryBuilderTrait;
use Mockery as m;

class WecounselTest extends \PHPUnit_Framework_TestCase
{
    use QueryBuilderTrait;

    protected $provider;

    protected function setUp()
    {
        $this->provider = new \Stevenmaguire\OAuth2\Client\Provider\Wecounsel([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_secret',
            'redirectUri' => 'redirect_url',
        ]);
    }

    protected function getMockJsonByFileName($filename)
    {
        return file_get_contents(sprintf('%s/data/%s', dirname(dirname(__DIR__)), $filename));
    }

    public function tearDown()
    {
        m::close();
        parent::tearDown();
    }

    public function testDefaultHost()
    {
        $this->assertEquals('https://api.wecounsel.com', $this->provider->getHost());
    }

    public function testUserProvidedDefaultHost()
    {
        $host = uniqid();
        $provider = new \Stevenmaguire\OAuth2\Client\Provider\Wecounsel([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_secret',
            'redirectUri' => 'redirect_url',
            'host' => $host
        ]);

        $this->assertEquals($host, $provider->getHost());
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }


    public function testScopes()
    {
        $scopeSeparator = ' ';
        $options = ['scope' => [uniqid(), uniqid()]];
        $query = ['scope' => implode($scopeSeparator, $options['scope'])];
        $url = $this->provider->getAuthorizationUrl($options);
        $encodedScope = $this->buildQueryString($query);
        $this->assertContains($encodedScope, $url);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);

        $this->assertEquals('/oauth/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];

        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);

        $this->assertEquals('/oauth/token', $uri['path']);
    }

    public function testGetAccessToken()
    {
        $accessTokenResponse = $this->getMockJsonByFileName('access_token.json');
        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $response->shouldReceive('getBody')->andReturn($accessTokenResponse);
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertLessThanOrEqual(time() + 7200, $token->getExpires());
        $this->assertGreaterThanOrEqual(time(), $token->getExpires());
        $this->assertEquals('mock_refresh_token', $token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserData()
    {
        $accessTokenResponse = $this->getMockJsonByFileName('access_token.json');
        $resourceOwnerResponse = $this->getMockJsonByFileName('resource_owner.json');
        $resourceOwnerArray = json_decode($resourceOwnerResponse, true);
        $userId = $resourceOwnerArray['data']['id'];
        $name = implode(' ', array_filter([
            $resourceOwnerArray['data']['attributes']['first_name'],
            $resourceOwnerArray['data']['attributes']['last_name']
        ]));
        $email = $resourceOwnerArray['data']['attributes']['email'];

        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getStatusCode')->andReturn(200);
        $postResponse->shouldReceive('getBody')->andReturn($accessTokenResponse);
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getStatusCode')->andReturn(200);
        $userResponse->shouldReceive('getBody')->andReturn($resourceOwnerResponse);
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getResourceOwner($token);

        $this->assertEquals($userId, $user->getId());
        $this->assertEquals($name, $user->getName());
        $this->assertEquals($email, $user->getEmail());
        $this->assertEquals($resourceOwnerArray, $user->toArray());
    }

    public function testUserDataFails()
    {
        $accessTokenResponse = $this->getMockJsonByFileName('access_token.json');
        $errorPayloads = [
            '{"error":"mock_error","error_description": "mock_error_description"}',
            '{"error":{"message":"mock_error"},"error_description": "mock_error_description"}',
            '{"foo":"bar"}'
        ];

        $testPayload = function ($payload) use ($accessTokenResponse) {
            $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $postResponse->shouldReceive('getStatusCode')->andReturn(200);
            $postResponse->shouldReceive('getBody')->andReturn($accessTokenResponse);
            $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);

            $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
            $userResponse->shouldReceive('getBody')->andReturn($payload);
            $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
            $userResponse->shouldReceive('getStatusCode')->andReturn(500);

            $client = m::mock('GuzzleHttp\ClientInterface');
            $client->shouldReceive('send')
                ->times(2)
                ->andReturn($postResponse, $userResponse);
            $this->provider->setHttpClient($client);

            $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

            try {
                $user = $this->provider->getResourceOwner($token);
                return false;
            } catch (\Exception $e) {
                $this->assertInstanceOf('\League\OAuth2\Client\Provider\Exception\IdentityProviderException', $e);
            }

            return $payload;
        };

        $this->assertCount(3, array_filter(array_map($testPayload, $errorPayloads)));
    }
}
