resource "elasticstack_elasticsearch_component_template" "timesketch-timelines" {
  name = "timesketch-timelines"

  template {
    mappings = jsonencode({
      # Timesketch mandatory fields
      properties = {
        datetime = {
          type = "date"
        }
        timestamp_desc = {
          type = "keyword"
        }
        data_type = {
          type = "keyword"
        }
        timesketch_label = {
          type = "nested"
          properties = {
            name = {
              type = "text"
              fields = {
                keyword = {
                  type = "keyword"
                }
              }
            }
            sketch_id = {
              type = "long"
            }
            user_id = {
              type = "long"
            }
          }
        }
        tag = {
          type = "keyword"
        }
        __ts_timeline_id = {
          type = "long"
        }
      }

      # The other fields are mapped as object or wildcard.
      dynamic_templates = [
        {
          object = {
            match_mapping_type = "object"
            mapping = {
              type = "object"
            }
          }
        },
        {
          wildcard = {
            match_mapping_type = "*"
            mapping = {
              type = "wildcard"
            }
          }
        }
      ]
    })

    settings = jsonencode({
      mapping = {
        total_fields = {
          limit = 20000
        }
      }
    })
  }

  elasticsearch_connection {
    endpoints = [<ENDPOINT>]
    username  = <USERNAME>
    password  = <PASSWORD>
  }
}
