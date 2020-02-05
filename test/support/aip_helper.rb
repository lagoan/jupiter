module AipHelper
  extend ActiveSupport::Concern

  protected

  def generate_graph_from_n3(data)
    graph = RDF::Graph.new
    RDF::Reader.for(:n3).new(data) do |reader|
      reader.each_statement do |statement|
        graph << statement
      end
    end

    graph
  end

  def check_file_order_xml(data)
    xsd = Nokogiri::XML::Schema(File.open(file_fixture('file-order.xsd')))
    doc = Nokogiri::XML(data)
    xsd.valid?(doc)
  end

  def get_n3_graph(url)
    get url
    generate_graph_from_n3(response.body)
  end

  def file_paths_json_schema
    {
      type: 'object',
      properties: {
        files: {
          type: 'array',
          items: {
            type: 'object',
            properties: {
              file_name: {
                type: 'string'
              },
              file_path: {
                type: 'string'
              },
              file_uuid: {
                type: 'string'
              }
            }
          }
        }
      },
      required: [:files]
    }
  end

  def create_entity(
    entity_class: Item,
    parameters: {},
    files: [],
    community: nil,
    collection: nil
  )
    community ||= communities(:fancy_community)
    collection ||= collections(:fancy_collection)

    entity = entity_class.new(parameters).tap do |current_entity|
      current_entity.add_to_path(community.id, collection.id)
      current_entity.save!
    end

    Sidekiq::Testing.inline! do
      entity.add_and_ingest_files(
        files.map do |file|
          File.open(file, 'r')
        end
      )
    end

    entity
  end
end
