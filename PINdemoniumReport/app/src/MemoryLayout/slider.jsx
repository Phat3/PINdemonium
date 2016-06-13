import React from 'react';

import SliderItem from './sliderItem.jsx'


class Slider extends React.Component {

   constructor(){
    super()
    this.state = { activeItem : 0 }
    this.navigateToDump = this.navigateToDump.bind(this)
  }


  navigateToDump(id){
    this.setState({ activeItem : id })
  }

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
      if( i === this.state.activeItem){
        items.push(<SliderItem key={i} id={i} onSelect={this.navigateToDump} active={true}/>)
      }
      else{
        items.push(<SliderItem key={i} id={i} onSelect={this.navigateToDump} active={false}/>)
      }
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
