class JupiterCore::SolrServices::Client

  include Singleton

  SOLR_CONFIG = YAML.safe_load(ERB.new(File.read(Rails.root.join('config', 'solr.yml'))).result,
                               [], [], true)[Rails.env].symbolize_keys

  def connection
    @connection ||= RSolr.connect url: SOLR_CONFIG[:url]
  end

end
