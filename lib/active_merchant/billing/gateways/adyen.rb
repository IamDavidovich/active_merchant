module ActiveMerchant #:nodoc:
  module Billing #:nodoc:
    class AdyenGateway < Gateway
      self.test_url = 'https://pal-test.adyen.com/pal/servlet/Payment/v12'
      self.live_url = 'https://pal-live.adyen.com/pal/servlet/Payment/v12'

      self.supported_countries = ['US']                                           # @todo Figure this out at all
      self.default_currency = 'USD'                                               # @todo Confirm this
      self.supported_cardtypes = [:visa, :master, :american_express, :discover,
                                  :diners_club, :jcb]                             # @todo Confirm this

      self.homepage_url = 'http://www.adyen.com/'
      self.display_name = 'Adyen'

      # Adyen expects non-decimal values
      self.money_format = :cents

      STANDARD_ERROR_CODE_MAPPING = {}

      def initialize(options={})
        # * <tt>:order_id</tt> - The order number
        # * <tt>:ip</tt> - The IP address of the customer making the purchase
        # * <tt>:customer</tt> - The name, customer number, or other information that identifies the customer
        # * <tt>:invoice</tt> - The invoice number
        # * <tt>:merchant</tt> - The name or description of the merchant offering the product
        # * <tt>:description</tt> - A description of the transaction
        # * <tt>:email</tt> - The email address of the customer
        # * <tt>:currency</tt> - The currency of the transaction.  Only important when you are using a currency that is not the default with a gateway that supports multiple currencies.
        # * <tt>:billing_address</tt> - A hash containing the billing address of the customer.
        # * <tt>:shipping_address</tt> - A hash containing the shipping address of the customer.

        requires!(options, :merchant, :username, :password) # @todo Confirm this
        super
      end

      def purchase(money, payment_method, options={})
        authorize(money, payment_method, options) # @todo Figure out whether this should just be separate auth and capture calls.
      end

      def authorize(money, payment_method, options={})
        request = {}
        add_amount(request, money, options)
        add_invoice(request, options)
        add_customer_data(request, options)
        add_payment_method(request, payment_method)

        commit(:authorise, request)
      end

      def capture(money, authorization, options={})
        commit('capture', request)
      end

      def refund(money, authorization, options={})
        commit('refund', request)
      end

      def void(authorization, options={})
        commit('void', request)
      end

      def verify(credit_card, options={})
        MultiResponse.run(:use_first_response) do |r|
          r.process { authorize(100, credit_card, options) }
          r.process(:ignore_result) { void(r.authorization, options) }
        end
      end

      def supports_scrubbing?
        true
      end

      def scrub(transcript)
        transcript
      end

      private

      def add_customer_data(request, options)
        request[:shopperIP] = options[:ip]
        request[:shopperEmail] = options[:email]
        request[:shopperReference] = options[:shopperEmail] # @todo should this be the customer ID? Can we get that?
      end

      def add_merchant_data(request, options={})
        request[:merchantAccount] = options.empty? ? @options[:merchant] : options[:merchant]
      end

      def add_address(request, creditcard, options)
        # :name
        # :company
        # :address1
        # :address2
        # :city
        # :state
        # :country
        # :zip
        # :phone
      end

      def add_invoice(request, options)
        request[:reference] = options[:invoice] # @todo This probably shouldn't be the invoice since an invoice could have multiple payments
        # request[:merchantOrderReference] = options[:order] # @todo would be good to add this if possible
      end

      def add_amount(request, money, options)
        request[:amount] = {
          value: amount(money),
          currency: (options[:currency] || currency(money))
        }
      end

      def add_payment_method(request, payment_method)
        # @todo Enable the ten million other payment methods
        raise ArgumentError, 'Unsupported funding source provided' unless supported_cardtypes.include? card_brand(payment_method).to_sym
        add_credit_card(request, payment_method)
      end

      def add_credit_card(request, payment_method)
        request[:card] = {
          expiryMonth: format(payment_method.month, :two_digits),
          expiryYear: format(payment_method.year, :four_digits),
          holderName: payment_method.name,
          number: payment_method.number,
          cvc: payment_method.verification_value
        }
      end

      def parse(body)
        JSON.parse(body, symbolize_names: true)
      end

      def commit(action, parameters)
        add_merchant_data(parameters)

        response = parse(ssl_post(url(action), request_data(action, parameters), headers))

        binding.pry

        Response.new(
          success_from(action, response),
          message_from(action, response),
          response,
          authorization: authorization_from(action, response),
          # avs_result: AVSResult.new(code: response["some_avs_response_key"]),
          # cvv_result: CVVResult.new(response["some_cvv_response_key"]),
          # error_code: error_code_from(response)
          test: test?
        )
      end

      def url(action)
        (test? ? test_url : live_url) + '/' + action.to_s
      end

      def success_from(action, response)
        return response[:resultCode] == 'Authorised' if action == :authorise
        response[:resultCode] == "[#{action.to_s}-received]"
      end

      def message_from(action, response)
        if success_from(action, response)
          'Succeeded'
        else
          response[:refusalReason] || "Error #{response[:errorCode]} - #{response[:message]}"
        end
      end

      def authorization_from(action, response)
        response[:pspReference]
      end

      def request_data(action, parameters = {})
        recursively_compact_hash(parameters).to_json
      end

      def error_code_from(response)
        unless success_from(response)
          # TODO: lookup error code for this response
        end
      end

      def headers
        {
          'Content-Type'  => 'application/json',
          'Authorization' => authorization_header
        }
      end

      def authorization_header
        'Basic ' + Base64.strict_encode64(@options[:username].to_s + ':' + @options[:password].to_s)
      end

      def recursively_compact_hash(hash)
        proc = Proc.new do |k, v|
          (v.kind_of?(Hash)) ? (v.delete_if(&proc); v.empty? ) : v.nil?
        end
        hash.delete_if &proc
      end
    end
  end
end
