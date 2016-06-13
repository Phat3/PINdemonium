import React from 'react';

import SliderItem from './sliderItem.jsx'


class Slider extends React.Component {

  render () {

    var olStyle = {
        listStyle : 'none',
        width : '100%',
        textAlign : 'center',
        paddingLeft : '0px',
        paddingTop : '20px',
    }
    /*
    var items = this.props.data.map(function(row){
      return <RegisterRow key={row.id} name={row.name} content={row.content}/>
    })
    */
    var items = []
    for (var i = 0; i <= 10; i++) {
      items.push(<SliderItem key={i} />)
    }

    return (
      <div>
         <ol style={olStyle}>
             {items}
          </ol>
      </div>
    );
  }
}

export default Slider;
